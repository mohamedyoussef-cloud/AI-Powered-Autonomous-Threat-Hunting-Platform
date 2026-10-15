# Backend regression tests

API, hunt-engine and ML inference/compatibility tests.

## Contents
- [`test_api.py`](test_api.py) — implementation of test api
- [`test_hunt_engine.py`](test_hunt_engine.py) — implementation of test hunt engine
- [`test_ml_triage.py`](test_ml_triage.py) — implementation of test ml triage
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

Run `python -m pytest tests -q` from `backend/`. The hunt fixture uses an isolated synthetic database. The optional full ML tests are skipped when the 142 MB frozen model bundle is absent; a skip is not evidence of inference success.

[Related overview](../README.md)
