# Threat-hunting research package

Python research components for environmental suitability, telemetry inventories and ATT&CK-grounded detection pipeline stages.

## Contents
- [`environment/`](environment/) — builders for platform profiles, technique applicability, telemetry readiness, Sigma knowledge gaps and prioritization scores.
- [`ingestion/`](ingestion/) — programs for building canonical source inventories and normalized evidence records.
- [`phase3/`](phase3/) — scripts coordinating technique prioritization, hypothesis routing, eligibility, grounded plans and Sigma generation/validation.
- [`telemetry/`](telemetry/) — aTT&CK data-component requirements, generic evidence construction and capability-resolution audits.

## Interpretation and usage

The integrated FastAPI interface is a separate package under `backend/app/` and does not automatically recompute these offline outputs.

[Related overview](../README.md)
