# Data preparation and normalization

Shared source preparation, normalization, schema validation and feature-contract helpers.

## Contents
- [`__init__.py`](__init__.py) — Python package initialization
- [`bots_preparation.py`](bots_preparation.py) — implementation of bots preparation
- [`evtx_preparation.py`](evtx_preparation.py) — implementation of evtx preparation
- [`feature_contracts.py`](feature_contracts.py) — implementation of feature contracts
- [`normalization.py`](normalization.py) — implementation of normalization
- [`schema_validation.py`](schema_validation.py) — implementation of schema validation

## Interpretation and usage

The files cover ATT&CK-aligned security data preparation. Keep the GUIDE/XGBoost ML source fields distinct from canonical EVTX or Sigma fields unless explicitly validated.

[Related overview](../README.md)
