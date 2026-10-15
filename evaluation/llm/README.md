# Qwen3-8B: locked Sigma-generation evaluation

This area documents the **Qwen3-8B QLoRA detection-generation study**. This is a rule-generation benchmark, **not** the XGBoost GUIDE alert triage study and not an evaluation of end-to-end live detections.

## Authoritative corpus

Location: [`datasets/llm/qwen3_sigma_training_v1/`](../../datasets/llm/qwen3_sigma_training_v1/)

| Partition | Records |
| --- | ---: |
| Train | 2,322 |
| Validation | 270 |
| Frozen test | 286 |

Partition SHA-256 values recorded with the locked research run:

- Train: `2bedacf399c64c9ac3c651f9e290b872bcec8f998fdfa162a8f4bf6ec31c97c9`
- Validation: `1e30ddfe1b9959a5c6cbfce2a4fdada1bebfb51eaacd9af8707838a36b9467ec`
- Frozen test: `2dae6ee9a03715c7c28263749c389dd6d50bf64974e54ec72cc8fd1819dc43c3`

Recorded adaptation: QLoRA, 1 epoch, LoRA rank 16 / alpha 32, learning rate 2e-4, max sequence length 2048. These figures describe the locked run only; use the underlying training and evaluation records for reproducibility. Never train or tune on the frozen test split.

## Frozen benchmark: 286 records

| Gate | Base Qwen3-8B | Fine-tuned Qwen3-8B |
| --- | ---: | ---: |
| Strict YAML | 79.02% | 87.76% |
| pySigma parse validity | 61.89% | 80.42% |
| No-blocker pass | 0.00% | **77.97% (223/286)** |
| ATT&CK technique exact | 9.09% | 83.57% |
| ATT&CK tactic exact | 0.70% | 85.31% |
| Log source exact | 73.43% | 78.67% |
| Level exact | 12.94% | 81.47% |

These gates assess generated Sigma artifacts, not search precision or confirmed threat findings.

## Evidence layout

- [`base-model/`](base-model/) — unadapted baseline outcomes.
- [`fine-tuned-model/`](fine-tuned-model/) — frozen candidate outcomes.
- [`validation/`](validation/) — pre-frozen validation outputs.
- [`training/`](training/) — training-run records.

**Historical result warning:** [`experiments/llm_finetuning/`](../../experiments/llm_finetuning/) contains a separate **398-example exploratory experiment**. Its headline percentages must not be mixed with the locked 286-example benchmark.

The model weights/inference endpoint are not shipped in this repository. Consult [validation boundaries](../../docs/VALIDATION_AND_LIMITATIONS.md).
