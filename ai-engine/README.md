# AI component map (architecture only)

This tree preserves the initial logical decomposition of the AI layer. Its child directories are **not standalone deployed model services**; production-oriented implementations have moved into the research source and FastAPI application.

| Logical module | Implementation / evidence |
| --- | --- |
| [Hypothesis engine](hypothesis_engine/) | [`src/threat_hunting/phase3/hypothesis_engine/`](../src/threat_hunting/phase3/hypothesis_engine/) and [`backend/app/services/phase3_hypothesis.py`](../backend/app/services/phase3_hypothesis.py) |
| [Rule/query generation](query_generator/) | [`backend/app/services/detection_providers.py`](../backend/app/services/detection_providers.py), [`artifacts/sigma/`](../artifacts/sigma/) and [`artifacts/splunk/`](../artifacts/splunk/) |
| [Prompt research](prompt_templates/) | [`scripts/llm/`](../scripts/llm/) and [`evaluation/llm/`](../evaluation/llm/) |
| [ML triage](ml_classifier/) | [`backend/app/services/ml_triage.py`](../backend/app/services/ml_triage.py) plus frozen evaluation metadata |

The Qwen inference provider requires separate configuration. The GUIDE-trained XGBoost model is an **analyst-assistance component**, not a standalone autonomous false-positive suppression system. See the [system architecture](../docs/PLATFORM_ARCHITECTURE.md).
