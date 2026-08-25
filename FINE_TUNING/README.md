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
