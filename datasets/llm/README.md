# LLM Datasets

## Layout

### supervised_sigma_v1/
Leakage-resistant SigmaHQ selection artifacts, family grouping, near-duplicate analysis, and split manifests.

### 	raining_corpus_v1/
General supervised instruction corpus produced from the selected Sigma dataset.

### qwen3_sigma_training_v1/
Authoritative context-constrained corpus used by the documented Qwen3-8B QLoRA training and frozen-test evaluation.

| Split | Records |
| --- | ---: |
| Train | 2,322 |
| Validation | 270 |
| Frozen test | 286 |

The frozen-test split is preserved for final evaluation and is not used during training.