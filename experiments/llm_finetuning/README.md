# Historical LLM fine-tuning experiment — 398-example run

This folder records an **earlier** Qwen3-8B Sigma-generation experiment and strategy comparison. It is intentionally retained for research provenance, but **is not** the authoritative final locked benchmark.

## Archived files

- [`eval_results.json`](eval_results.json) — candidate outputs from the earlier evaluation.
- [`baseline_results.json`](baseline_results.json) — earlier baseline results.
- [`strategy_selection.json`](strategy_selection.json) — recorded strategy-selection metadata.

## Interpretation

The original exploratory run used a **398-example evaluation population**; any validity percentage associated with that run belongs to that protocol alone. The subsequent locked benchmark uses **286 frozen examples**, with a **223/286 (77.97%) no-blocker pass** for the fine-tuned model and 0/286 for its base comparator. These are **different experiments** and must not be compared or combined as though they evaluated the same split and gate.

Use [`evaluation/llm/README.md`](../../evaluation/llm/README.md) and [`datasets/llm/qwen3_sigma_training_v1/`](../../datasets/llm/qwen3_sigma_training_v1/) for the authoritative MSc evaluation. The historical checkpoint/infrastructure details are not required for public release, and this directory is not an independently deployable LLM provider.
