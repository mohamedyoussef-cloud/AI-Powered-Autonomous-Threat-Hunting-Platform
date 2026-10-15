# FastAPI HTTP routes

API endpoints for campaigns, analysts, findings, generated rules, source control, datasets, operations and ML triage.

## Contents
- [`generator.py`](generator.py) — implementation of generator
- [`campaigns.py`](campaigns.py) — implementation of campaigns
- [`ml_triage.py`](ml_triage.py) — implementation of ml triage
- [`findings.py`](findings.py) — implementation of findings
- **Additional tracked files:** 14 (see directory listing for complete inventory).

## Interpretation and usage

Permissions and status responses must reflect available services. The generation route exposes the actual provider/method and gate outcome; do not conflate template or retrieval output with Qwen inference.

[Related overview](../../README.md)
