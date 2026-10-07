# LLM Training and Evaluation

## Model

Base model: Qwen/Qwen3-8B

Revision: 968826d9c46dd6066d109eabc6255188de91218

Adaptation method: QLoRA

## Authoritative Training Corpus

datasets/llm/qwen3_sigma_training_v1/

| Split | Records |
| --- | ---: |
| Train | 2,322 |
| Validation | 270 |
| Frozen test | 286 |

SHA256:

- train: 2bedacf399c64c9ac3c651f9e290b872bcec8f998fdfa162a8f4bf6ec31c97c9
- validation: 1e30ddfe1b9959a5c6cbfce2a4fdada1bebfb51eaacd9af8707838a36b9467ec
- test: 2dae6ee9a03715c7c28263749c389dd6d50bf64974e54ec72cc8fd1819dc43c3

## Training Run

| Parameter | Value |
| --- | --- |
| Training records | 2322 |
| Validation records | 270 |
| Epochs | 1.0 |
| Learning rate | 0.0002 |
| LoRA rank | 16 |
| LoRA alpha | 32 |
| Max sequence length | 2048 |
| Optimizer | paged_adamw_8bit |
| GPU | NVIDIA A16 |

## Frozen-Test Benchmark

Population: **286**

| Metric | Base | Fine-tuned |
| --- | ---: | ---: |
| Strict YAML | 79.02% | 87.76% |
| pySigma parse valid | 61.89% | 80.42% |
| No-blocker pass | 0.00% | 77.97% |
| ATT&CK technique exact | 9.09% | 83.57% |
| ATT&CK tactic exact | 0.70% | 85.31% |
| Log source exact | 73.43% | 78.67% |
| Level exact | 12.94% | 81.47% |

The fine-tuned model is evaluated as a detection-generation component, not as an authoritative production decision maker.