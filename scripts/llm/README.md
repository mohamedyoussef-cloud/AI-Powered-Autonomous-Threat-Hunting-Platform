# Qwen training and evaluation scripts

Training and evaluation procedures for research Sigma generation, plus telemetry-resolver experiments.

## Contents
- [`train_qwen3_sigma_qlora.py`](train_qwen3_sigma_qlora.py) — implementation of train qwen3 sigma qlora
- [`evaluate_sigma_generation_v2.py`](evaluate_sigma_generation_v2.py) — implementation of evaluate sigma generation v2
- **Additional tracked files:** 3 (see directory listing for complete inventory).

## Interpretation and usage

GPU-intensive procedures are optional research reproduction tasks. `train_qwen3_sigma_qlora.py` does not define the running backend provider; check recorded split contracts before any training.

[Related overview](../../docs/README.md)
