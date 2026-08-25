# Hypothesis → Sigma Rule: Fine-Tuned LLM Component

## Overview
Converts natural-language threat hunting hypotheses into
structured Sigma detection rules using fine-tuned Qwen3-8B.

## Model
- Base model: Qwen/Qwen3-8B
- Adapter: mar7788yam/hypothesis-to-sigma-qwen3-8b (HuggingFace, private)
- Method: QLoRA fine-tuning (4-bit quantization)
- Trainable parameters: 43.6M / 8.2B (0.53%)

## Results
| Approach                  | Valid Sigma | Technique Match |
|---------------------------|-------------|-----------------|
| Prompt-Only (no training) | 0.0%        | 52.5%           |
| Fine-Tuned QLoRA (ours)   | 99.0%       | 66.6%           |

## Training Details
- Dataset: 3,770 train / 245 val / 398 test
- Epochs: 3
- Training time: ~10 hours
- Best checkpoint: Step 450 (val loss: 1.006)

## How to Use for backend phase ##
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch

def load_model():
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    tokenizer = AutoTokenizer.from_pretrained(
        "mar7788yam/hypothesis-to-sigma-qwen3-8b"
    )
    base = AutoModelForCausalLM.from_pretrained(
        "Qwen/Qwen3-8B",
        quantization_config=bnb_config,
        device_map={"": 0},
    )
    model = PeftModel.from_pretrained(
        base, "mar7788yam/hypothesis-to-sigma-qwen3-8b"
    )
    return model, tokenizer

def generate_sigma(hypothesis, model, tokenizer):
    prompt = f"### Hypothesis:\n{hypothesis}\n\n### Sigma Detection:\n"
    inputs = tokenizer(prompt, return_tensors="pt",
                      truncation=True, max_length=512).to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=1200,
            do_sample=False,
            repetition_penalty=1.1,
            pad_token_id=tokenizer.eos_token_id,
        )
    length = inputs["input_ids"].shape[1]
    return tokenizer.decode(outputs[0][length:], skip_special_tokens=True)

## Output Files
- eval_results.json       : fine-tuned model results on 398 test examples
- baseline_results.json   : base model results on 398 test examples
- final_adapter/          : saved LoRA adapter weights (175MB)
- task52_strategy_selection.json : strategy comparison results





# PIPELINE:

## Pipeline

```
╔══════════════════════════════════════════════════════╗
║       Hypothesis → Sigma Fine-Tuning Pipeline        ║
║                  Qwen3-8B + QLoRA                    ║
╚══════════════════════════════════════════════════════╝

Phase 1: ENVIRONMENT SETUP
  CUDA 12.4 GPU (15.69 GB VRAM)
  PyTorch 2.5.1 + bitsandbytes 0.50.1
          ↓
Phase 2: BASE MODEL LOADING
  Qwen3-8B loaded in 4-bit QLoRA
  Normal: ~33GB → With 4-bit: ~5GB only
          ↓
Phase 3: LoRA ADAPTER
  Trainable: 43M / 8.2B params (0.53%)
  Target: q,k,v,o,gate,up,down projections
          ↓
Phase 4: DATA PREPARATION
  train.jsonl  → 3,770 examples
  val.jsonl    →   245 examples
  test.jsonl   →   398 examples
  Format: Hypothesis (input) → Sigma Rule (output)
          ↓
Phase 5: TRAINING
  Epochs: 3  |  Time: ~10 hours
  Custom BF16LossTrainer (saves ~600MB VRAM)
  Step  | Train Loss | Val Loss
  50    |   8.77     |  1.192
  150   |   6.73     |  1.094
  300   |   5.59     |  1.054
  450   |   5.24     |  1.006  ← BEST
  708   |   4.57     |  1.033
          ↓
Phase 6: BEST CHECKPOINT
  Step 450 → lowest val loss: 1.006
  Saved to: ./final_adapter (175MB)
          ↓
Phase 7: HUGGINGFACE BACKUP
  mar7788yam/hypothesis-to-sigma-qwen3-8b
  Adapter: 175MB + Tokenizer: 11.4MB
          ↓
Phase 8: EVALUATION (Task 51)
  Fine-tuned model on 398 test examples
  Valid Sigma: 394/398 = 99.0% ✅
          ↓
Phase 9: BASELINE (Task 49)
  Base model (no training) on 398 examples
  Valid Sigma: 0/398 = 0.0% ❌
          ↓
FINAL COMPARISON
  Base Model  →  0%  ❌
  Fine-Tuned  → 99%  ✅
  Improvement → +99% 🚀
```
