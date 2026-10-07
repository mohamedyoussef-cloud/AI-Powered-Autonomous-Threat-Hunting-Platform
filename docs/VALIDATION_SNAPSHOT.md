# Validation Snapshot

## Detection Pipeline

| Measure | Result |
| --- | ---: |
| Detection plans | 505 |
| Sigma rules | 540 |
| Sigma structural validation | 540 / 540 |
| Sigma-to-Splunk compilation | 540 / 540 |
| Runtime execution-ready paths | 404 |
| Deferred paths | 14 |

## Runtime Hunt Validation

| Measure | Result |
| --- | ---: |
| Runtime executions | 404 |
| Zero-result executions with incomplete raw visibility | 381 |
| Non-zero candidate paths | 22 |
| Execution errors | 1 |
| Validated findings | 0 |

The zero-result population is not interpreted as verified negative activity because raw-event visibility is incomplete for portions of the underlying dataset.

The 22 non-zero candidates were evaluated for broad-keyword contribution and candidate validity. None met the current criteria for promotion to validated hunt findings.

## LLM Evaluation

Frozen-test population: **286**

| Metric | Base Qwen3-8B | Fine-tuned Qwen3-8B |
| --- | ---: | ---: |
| YAML validity | 79.02% | 87.76% |
| pySigma parse validity | 61.89% | 80.42% |
| No-blocker pySigma pass | 0.00% | 77.97% |
| ATT&CK technique exact | 9.09% | 83.57% |
| ATT&CK tactic exact | 0.70% | 85.31% |
| Log source exact | 73.43% | 78.67% |
| Level exact | 12.94% | 81.47% |

Separate validation population: **270**

- pySigma parse validity: 81.85%
- no-blocker pySigma pass: 81.11%

Production reliability is provided by the broader deterministic pipeline, including telemetry grounding, eligibility controls, Sigma validation, query compilation, runtime telemetry checks, and finding validation.