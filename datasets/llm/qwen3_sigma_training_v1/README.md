# Locked Qwen3 Sigma corpus

Train/validation/frozen test splits used for the research Qwen3-8B QLoRA evaluation.

## Contents
- [`context_length_summary.json`](context_length_summary.json) — input length eligibility summary
- [`train.jsonl`](train.jsonl) — versioned line-delimited records
- [`validation.jsonl`](validation.jsonl) — versioned line-delimited records
- [`test.jsonl`](test.jsonl) — versioned line-delimited records
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

Recorded split sizes: train 2,322; validation 270; frozen test 286. The frozen split must not be reused for further training or tuning; see `evaluation/llm/README.md`.

[Related overview](../../../docs/README.md)
