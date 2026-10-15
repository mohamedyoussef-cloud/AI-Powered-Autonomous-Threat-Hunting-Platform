# Sigma-generation datasets

Training and frozen evaluation corpora, schema contracts and selection/audit manifests for the detection-generation research.

## Contents
- [`qwen3_sigma_training_v1/`](qwen3_sigma_training_v1/) — train/validation/frozen test splits used for the research Qwen3-8B QLoRA evaluation.
- [`supervised_sigma_v1/`](supervised_sigma_v1/) — policy, selection summary, family indexes and split manifests for SigmaHQ-assisted corpus preparation.
- [`training_corpus_v1/`](training_corpus_v1/) — earlier curated train/validation/test partitions and their build summaries and schema.

## Interpretation and usage

Do not mix exploratory corpora and the authoritative Qwen3 benchmark. The locked corpus is in `qwen3_sigma_training_v1/`.

[Related overview](../../docs/README.md)
