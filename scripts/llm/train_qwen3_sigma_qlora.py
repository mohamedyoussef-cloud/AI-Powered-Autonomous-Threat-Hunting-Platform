#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import random
import time
from pathlib import Path

import torch
from torch.nn.utils.rnn import pad_sequence
from torch.utils.data import Dataset
import transformers
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    Trainer,
    TrainingArguments,
)
import peft
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_jsonl(path: Path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class SigmaChatDataset(Dataset):
    def __init__(self, rows, tokenizer, max_length: int):
        self.items = []
        lengths = []
        supervised_lengths = []

        for row in rows:
            messages = row["messages"]
            if len(messages) != 3:
                raise ValueError(f"{row.get('example_id')}: expected exactly 3 messages")
            if [m["role"] for m in messages] != ["system", "user", "assistant"]:
                raise ValueError(f"{row.get('example_id')}: unexpected role order")

            prompt = tokenizer.apply_chat_template(
                messages[:2],
                tokenize=True,
                add_generation_prompt=True,
                enable_thinking=False,
            )["input_ids"]

            full = tokenizer.apply_chat_template(
                messages,
                tokenize=True,
                add_generation_prompt=False,
                enable_thinking=False,
            )["input_ids"]

            if len(full) > max_length:
                raise ValueError(
                    f"{row.get('example_id')}: {len(full)} tokens exceeds max_length={max_length}; "
                    "this script never truncates examples"
                )

            if full[: len(prompt)] != prompt:
                raise ValueError(
                    f"{row.get('example_id')}: prompt is not an exact prefix of full chat template"
                )

            labels = [-100] * len(prompt) + full[len(prompt) :]
            if not any(x != -100 for x in labels):
                raise ValueError(f"{row.get('example_id')}: no supervised assistant tokens")

            self.items.append(
                {
                    "input_ids": torch.tensor(full, dtype=torch.long),
                    "labels": torch.tensor(labels, dtype=torch.long),
                    "example_id": row["example_id"],
                }
            )
            lengths.append(len(full))
            supervised_lengths.append(sum(x != -100 for x in labels))

        self.lengths = lengths
        self.supervised_lengths = supervised_lengths

    def __len__(self):
        return len(self.items)

    def __getitem__(self, idx):
        return self.items[idx]


class AssistantOnlyCollator:
    def __init__(self, pad_token_id: int):
        self.pad_token_id = pad_token_id

    def __call__(self, features):
        ids = [x["input_ids"] for x in features]
        labels = [x["labels"] for x in features]

        input_ids = pad_sequence(
            ids,
            batch_first=True,
            padding_value=self.pad_token_id,
        )
        label_ids = pad_sequence(
            labels,
            batch_first=True,
            padding_value=-100,
        )
        attention_mask = input_ids.ne(self.pad_token_id).long()

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": label_ids,
        }


def token_stats(dataset: SigmaChatDataset):
    q = sorted(dataset.lengths)
    n = len(q)

    def pct(p):
        return q[int(p * (n - 1))]

    return {
        "count": n,
        "min": min(q),
        "p50": pct(0.50),
        "p90": pct(0.90),
        "p95": pct(0.95),
        "p99": pct(0.99),
        "max": max(q),
        "supervised_tokens_total": int(sum(dataset.supervised_lengths)),
    }


def make_training_args(output_dir: Path, cfg: dict, smoke: bool):
    sig = inspect.signature(TrainingArguments.__init__).parameters
    kwargs = {
        "output_dir": str(output_dir),
        "per_device_train_batch_size": cfg["per_device_train_batch_size"],
        "per_device_eval_batch_size": cfg["per_device_eval_batch_size"],
        "gradient_accumulation_steps": cfg["gradient_accumulation_steps"],
        "num_train_epochs": cfg["num_train_epochs"],
        "learning_rate": cfg["learning_rate"],
        "lr_scheduler_type": cfg["lr_scheduler_type"],
        # Transformers v5 uses warmup_steps; a float in [0,1) is
        # interpreted as a ratio of total optimizer steps.
        "weight_decay": cfg["weight_decay"],
        "max_grad_norm": cfg["max_grad_norm"],
        "logging_steps": cfg["logging_steps"],
        "bf16": True,
        "fp16": False,
        "gradient_checkpointing": True,
        "gradient_checkpointing_kwargs": {"use_reentrant": False},
        "optim": cfg["optim"],
        "seed": cfg["seed"],
        "data_seed": cfg["seed"],
        "report_to": "none",
        "remove_unused_columns": False,
        "save_strategy": "no",
    }

    if "warmup_ratio" in sig:
        kwargs["warmup_ratio"] = cfg["warmup_ratio"]
    elif "warmup_steps" in sig:
        kwargs["warmup_steps"] = cfg["warmup_ratio"]
    else:
        raise RuntimeError("TrainingArguments supports neither warmup_ratio nor warmup_steps")

    eval_key = "eval_strategy" if "eval_strategy" in sig else "evaluation_strategy"
    kwargs[eval_key] = "no" if smoke else cfg["eval_strategy"]

    if smoke:
        kwargs["max_steps"] = 1
        kwargs["num_train_epochs"] = 1.0

    unsupported = [k for k in kwargs if k not in sig]
    if unsupported:
        raise RuntimeError(f"Unsupported TrainingArguments fields: {unsupported}")

    return TrainingArguments(**kwargs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--dataset-dir", type=Path, required=True)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument(
        "--smoke-longest",
        action="store_true",
        help="Run one optimizer step on the longest training example; save no adapter.",
    )
    args = ap.parse_args()

    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    cfg = json.loads(args.config.read_text(encoding="utf-8"))

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required")
    if torch.cuda.device_count() != 1:
        print(f"WARNING visible CUDA devices={torch.cuda.device_count()}; this run is designed for one GPU")
    if not torch.cuda.is_bf16_supported():
        raise RuntimeError("bf16 is not supported by this GPU/runtime")

    random.seed(cfg["seed"])
    torch.manual_seed(cfg["seed"])

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        local_files_only=True,
    )
    tokenizer.padding_side = "right"
    if tokenizer.pad_token_id is None:
        if tokenizer.eos_token_id is None:
            raise RuntimeError("Tokenizer has neither pad_token_id nor eos_token_id")
        tokenizer.pad_token = tokenizer.eos_token

    train_rows = read_jsonl(args.dataset_dir / "train.jsonl")
    val_rows = read_jsonl(args.dataset_dir / "validation.jsonl")

    train_ds = SigmaChatDataset(
        train_rows,
        tokenizer,
        cfg["max_sequence_length"],
    )
    val_ds = SigmaChatDataset(
        val_rows,
        tokenizer,
        cfg["max_sequence_length"],
    )

    train_stats = token_stats(train_ds)
    val_stats = token_stats(val_ds)

    print("TRAIN_STATS", json.dumps(train_stats, sort_keys=True))
    print("VAL_STATS", json.dumps(val_stats, sort_keys=True))
    print("LOSS_MASKING assistant_only")

    if args.smoke_longest:
        longest_idx = max(range(len(train_ds)), key=lambda i: train_ds.lengths[i])
        print(
            "SMOKE_LONGEST",
            train_ds.items[longest_idx]["example_id"],
            train_ds.lengths[longest_idx],
        )
        train_ds.items = [train_ds.items[longest_idx]]
        train_ds.lengths = [train_ds.lengths[longest_idx]]
        train_ds.supervised_lengths = [train_ds.supervised_lengths[longest_idx]]

    quant_cfg = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=quant_cfg,
        device_map={"": 0},
        dtype=torch.bfloat16,
        local_files_only=True,
        low_cpu_mem_usage=True,
    )
    model.config.use_cache = False

    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
    )

    target_modules = cfg["lora_target_modules"]
    found = {
        name
        for name, _ in model.named_modules()
        for target in target_modules
        if name.endswith(target)
    }
    missing = [
        target
        for target in target_modules
        if not any(name.endswith(target) for name in found)
    ]
    if missing:
        raise RuntimeError(f"LoRA target modules not found: {missing}")

    lora_cfg = LoraConfig(
        r=cfg["lora_r"],
        lora_alpha=cfg["lora_alpha"],
        lora_dropout=cfg["lora_dropout"],
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=target_modules,
    )
    model = get_peft_model(model, lora_cfg)
    model.print_trainable_parameters()

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    training_args = make_training_args(
        output_dir,
        cfg,
        args.smoke_longest,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=None if args.smoke_longest else val_ds,
        data_collator=AssistantOnlyCollator(tokenizer.pad_token_id),
    )

    start = time.time()
    result = trainer.train()
    elapsed = time.time() - start

    peak_gb = torch.cuda.max_memory_allocated() / 1024**3
    reserved_gb = torch.cuda.max_memory_reserved() / 1024**3
    print(f"PEAK_VRAM_ALLOC_GB {peak_gb:.2f}")
    print(f"PEAK_VRAM_RESERVED_GB {reserved_gb:.2f}")

    if args.smoke_longest:
        print("SMOKE_STATUS PASS")
        return

    trainer.save_model(str(output_dir / "final_adapter"))
    tokenizer.save_pretrained(str(output_dir / "final_adapter"))

    eval_metrics = trainer.evaluate()

    manifest = {
        "run": "Qwen3-8B Sigma QLoRA",
        "status": "PASS",
        "base_model_snapshot": str(Path(args.model).resolve()),
        "dataset_dir": str(args.dataset_dir.resolve()),
        "dataset_files": {
            "train.jsonl": sha256(args.dataset_dir / "train.jsonl"),
            "validation.jsonl": sha256(args.dataset_dir / "validation.jsonl"),
        },
        "test_split_used": False,
        "assistant_only_loss": True,
        "thinking_enabled": False,
        "truncation_used": False,
        "train_stats": train_stats,
        "validation_stats": val_stats,
        "config": cfg,
        "versions": {
            "python": platform.python_version(),
            "torch": torch.__version__,
            "transformers": transformers.__version__,
            "peft": peft.__version__,
        },
        "gpu": torch.cuda.get_device_name(0),
        "elapsed_seconds": elapsed,
        "peak_vram_allocated_gb": peak_gb,
        "peak_vram_reserved_gb": reserved_gb,
        "train_metrics": result.metrics,
        "eval_metrics": eval_metrics,
    }

    (output_dir / "run_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("TRAINING_STATUS PASS")
    print(json.dumps(eval_metrics, sort_keys=True))


if __name__ == "__main__":
    main()
