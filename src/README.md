# Research pipeline source

Reusable ATT&CK context, telemetry processing, detection planning and data-normalization code, distinct from the web API.

## Contents
- [`threat_hunting/`](threat_hunting/) — python research components for environmental suitability, telemetry inventories and ATT&CK-grounded detection pipeline stages.
- [`threat_hunting_data/`](threat_hunting_data/) — shared source preparation, normalization, schema validation and feature-contract helpers.

## Interpretation and usage

The executable source modules live under `threat_hunting/` and `threat_hunting_data/`. Outputs from historical runs are versioned under `artifacts/`.

[Related overview](../docs/README.md)
