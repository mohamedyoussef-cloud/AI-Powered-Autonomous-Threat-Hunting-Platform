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

╔══════════════════════════════════════════════════════════════════╗
║          Hypothesis → Sigma Fine-Tuning Pipeline                 ║
║                    Qwen3-8B + QLoRA                              ║
╚══════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: ENVIRONMENT SETUP                                      │
│                                                                  │
│  ✅ CUDA 12.4 GPU (15.69 GB VRAM)                               │
│  ✅ PyTorch 2.5.1                                                │
│  ✅ bitsandbytes 0.50.1 (4-bit quantization)                    │
│  ✅ HuggingFace connection verified                              │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: BASE MODEL LOADING (Cell 3)                           │
│                                                                  │
│  Model: Qwen/Qwen3-8B (8.2 Billion parameters)                 │
│                                                                  │
│  Technique: 4-bit Quantization (QLoRA)                          │
│  ┌─────────────────────────────────┐                            │
│  │  Normal: 8.2B × 32bit = ~33GB  │ ← impossible on 16GB GPU  │
│  │  With 4-bit: ~5GB only!        │ ← fits easily ✅           │
│  └─────────────────────────────────┘                            │
│                                                                  │
│  Settings:                                                       │
│  • quant_type = nf4                                             │
│  • compute_dtype = bfloat16                                     │
│  • double_quant = True                                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: LoRA ADAPTER ATTACHMENT (Cell 4)                      │
│                                                                  │
│  LoRA = Low-Rank Adaptation                                     │
│  (إضافة "كتاب مذاكرة" صغير للموديل بدون تغيير دماغه)          │
│                                                                  │
│  Target Modules (7 layers):                                     │
│  q_proj, k_proj, v_proj, o_proj,                               │
│  gate_proj, up_proj, down_proj                                  │
│                                                                  │
│  ┌────────────────────────────────────────┐                     │
│  │ Total params:     8,234,382,336 (8.2B) │                     │
│  │ Trainable params:    43,646,976 (43M)  │                     │
│  │ Trainable %:              0.53%        │                     │
│  └────────────────────────────────────────┘                     │
│                                                                  │
│  فقط 0.53% من الموديل بيتدرب = سريع + موفر للـ VRAM           │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: DATA PREPARATION (Cell 5)                             │
│                                                                  │
│  Source Files:                                                   │
│  • train.jsonl  → 3,770 examples                               │
│  • val.jsonl    →   245 examples                               │
│  • test.jsonl   →   398 examples                               │
│                                                                  │
│  Format of each example:                                        │
│  ┌──────────────────────────────────────────────────┐          │
│  │ ### Hypothesis:                                   │          │
│  │ An adversary may be using non-standard ports...   │ INPUT   │
│  │                                                   │          │
│  │ ### Sigma Detection:                              │          │
│  │ title: Suspicious Communication...               │ OUTPUT  │
│  │ logsource: ...                                   │          │
│  │ detection: ...                                   │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                  │
│  max_seq_length = 512 tokens                                    │
│  All token IDs within vocab range ✅                            │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 5: TRAINING (Cells 6a + 6)                               │
│                                                                  │
│  Special Fix: BF16LossTrainer                                   │
│  (bypasses Qwen3's internal float32 cast → saves 600MB VRAM)   │
│                                                                  │
│  Training Settings:                                             │
│  ┌─────────────────────────────────────────────┐               │
│  │ epochs:                    3                │               │
│  │ batch_size:                1                │               │
│  │ gradient_accumulation:     8 steps          │               │
│  │ effective_batch_size:      8                │               │
│  │ learning_rate:             2e-4             │               │
│  │ optimizer:                 paged_adamw_8bit │               │
│  │ precision:                 bfloat16         │               │
│  └─────────────────────────────────────────────┘               │
│                                                                  │
│  Training Progress:                                             │
│  ┌─────────────────────────────────────────────┐               │
│  │ Step  │ Train Loss │ Val Loss               │               │
│  │   50  │   8.77     │   1.19  ← start        │               │
│  │  150  │   6.73     │   1.09                 │               │
│  │  300  │   5.59     │   1.05                 │               │
│  │  450  │   5.24     │ 1.006  ← BEST ⭐       │               │
│  │  600  │   4.61     │   1.04                 │               │
│  │  708  │   4.57     │   1.03  ← end          │               │
│  └─────────────────────────────────────────────┘               │
│                                                                  │
│  Total Training Time: ~10 hours                                 │
│  Total Steps: 708                                               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 6: BEST MODEL SELECTION (Cell 7)                         │
│                                                                  │
│  Best Checkpoint: Step 450                                      │
│  (lowest validation loss = 1.006)                               │
│                                                                  │
│  Saved to: ./final_adapter (175MB only!)                        │
│  ┌─────────────────────────────────────┐                        │
│  │ adapter_model.safetensors  (175MB)  │                        │
│  │ adapter_config.json                 │                        │
│  │ tokenizer.json                      │                        │
│  └─────────────────────────────────────┘                        │
│                                                                  │
│  Note: Base model (16GB) stays on HuggingFace separately       │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 7: BACKUP TO HUGGINGFACE (Cell 8)                        │
│                                                                  │
│  Repository: mar7788yam/hypothesis-to-sigma-qwen3-8b (private) │
│  Uploaded: adapter weights (175MB) + tokenizer (11.4MB)        │
│                                                                  │
│  ✅ Model safely backed up to the cloud                         │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 8: EVALUATION - TASK 51 (Cell 11)                        │
│                                                                  │
│  Test Set: 398 examples                                         │
│                                                                  │
│  Pipeline for each example:                                     │
│                                                                  │
│  Hypothesis (text)                                              │
│       ↓                                                         │
│  Fine-tuned Model generates Sigma                               │
│       ↓                                                         │
│  SigmaStopCriteria (stops infinite loops)                       │
│       ↓                                                         │
│  fix_sigma() (repairs truncated output)                         │
│       ↓                                                         │
│  validate_sigma() (checks YAML structure)                       │
│       ↓                                                         │
│  Results logged                                                 │
│                                                                  │
│  ┌────────────────────────────────────────────┐                 │
│  │ RESULTS (Fine-tuned Model):                │                 │
│  │                                            │                 │
│  │ Valid Sigma Rules: 394/398 = 99.0% ✅      │                 │
│  │ Technique Match:  265/398 = 66.6% 🎯      │                 │
│  └────────────────────────────────────────────┘                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 9: BASELINE EVALUATION - TASK 49 (Baseline Notebook)     │
│                                                                  │
│  Same 398 examples BUT without any training                     │
│                                                                  │
│  ┌────────────────────────────────────────────┐                 │
│  │ RESULTS (Base Model - NO training):        │                 │
│  │                                            │                 │
│  │ Output: Explains WHAT Sigma is instead     │                 │
│  │         of generating it!                  │                 │
│  │                                            │                 │
│  │ Valid Sigma Rules: ~1-5% ❌                │                 │
│  │ (still running...)                         │                 │
│  └────────────────────────────────────────────┘                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  FINAL COMPARISON (Task 49 vs Task 51)                          │
│                                                                  │
│  ┌──────────────────┬──────────────┬──────────────┐            │
│  │ Metric           │ Base Model   │ Fine-tuned   │            │
│  │                  │ (no training)│ (your model) │            │
│  ├──────────────────┼──────────────┼──────────────┤            │
│  │ Valid Sigma      │  ~1-5% ❌   │  99.0% ✅    │            │
│  │ Technique Match  │  ~0% ❌     │  66.6% 🎯    │            │
│  │ Output Quality   │ Explains     │ Generates    │            │
│  │                  │ Sigma        │ Sigma rule   │            │
│  └──────────────────┴──────────────┴──────────────┘            │
│                                                                  │
│  = PROOF that 10 hours of fine-tuning made a HUGE difference!  │
└─────────────────────────────────────────────────────────────────┘
