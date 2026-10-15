# Research experiments — index and interpretation

These folders preserve proposals and intermediate studies. Their original planning status may predate the recorded Sigma, Splunk and GUIDE results; they are **not** the current product readiness board.

| Experiment | Scope | Current evidence source |
| --- | --- | --- |
| [01 — Hypotheses](experiment_01_hypothesis_generation/) | ATT&CK-grounded hypothesis creation | [`artifacts/hypotheses/`](../artifacts/hypotheses/) |
| [02 — Query generation](experiment_02_query_generation/) | Sigma drafting and SPL compilation | [`artifacts/sigma/`](../artifacts/sigma/), [`artifacts/splunk/`](../artifacts/splunk/) |
| [03 — ML triage](experiment_03_false_positive_suppression/) | Alert-level model classification | [Frozen evaluation](../backend/app/data/ml_triage/ml_triage_production_v1/evaluation/frozen_test_final_v1.json) |
| [04 — Integrated hunt](experiment_04_end_to_end_hunt/) | Runtime hunting and review | [`artifacts/hunt-findings/`](../artifacts/hunt-findings/) |
| [Historical LLM fine-tuning](llm_finetuning/) | Older 398-example benchmark | [Locked 286-example benchmark](../evaluation/llm/README.md) |

**Evaluation discipline:** no claim of autonomously confirmed detection is supported by the recorded 404-hunt batch, and the frozen XGBoost macro-F1 of approximately 0.4523 is for held-out GUIDE organizations, not ordinary SIEM findings.
