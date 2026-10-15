# Detection and triage domain services

Services implement generation-provider selection, Sigma parsing/compilation, hunting, telemetry, context retrieval, dataset catalogs and risk-scoring orchestration.

## Contents
- [`detection_providers.py`](detection_providers.py) — implementation of detection providers
- [`sigma_engine.py`](sigma_engine.py) — implementation of sigma engine
- [`ml_triage.py`](ml_triage.py) — implementation of ml triage
- [`triage.py`](triage.py) — implementation of triage
- [`campaign_engine.py`](campaign_engine.py) — implementation of campaign engine
- **Additional tracked files:** 11 (see directory listing for complete inventory).

## Interpretation and usage

`ml_triage.py` enforces bundle integrity/feature compatibility; `triage.py` supplies an explicitly identified heuristic route when appropriate. The frozen model is advisory, not a verdict engine.

[Related overview](../../README.md)
