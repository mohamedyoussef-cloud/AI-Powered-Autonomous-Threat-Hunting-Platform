# Research data-preparation tests

Tests for telemetry normalization, feature contracts, EVTX preparation and BOTS handling.

## Contents
- [`test_bots_preparation.py`](test_bots_preparation.py) — implementation of test bots preparation
- [`test_evtx_preparation.py`](test_evtx_preparation.py) — implementation of test evtx preparation
- [`test_feature_contracts.py`](test_feature_contracts.py) — implementation of test feature contracts
- [`test_normalization.py`](test_normalization.py) — implementation of test normalization

## Interpretation and usage

Run root research tests independently of `backend/tests/`. Some tests may require only small synthetic inputs, while data-preparation scripts may need external data; do not imply a complete SIEM end-to-end acceptance test.

[Related overview](../docs/README.md)
