# Backend application package

FastAPI startup, request handlers, core configuration, Pydantic schemas and domain services.

## Contents
- [`core/`](core/) — application settings, SQLAlchemy initialization and shared security helpers.
- [`data/`](data/) — local SQLite state and optionally installed inference assets sit under the backend data directory.
- [`routers/`](routers/) — aPI endpoints for campaigns, analysts, findings, generated rules, source control, datasets, operations and ML triage.
- [`schemas/`](schemas/) — pydantic schemas for endpoint inputs, outputs and campaign payloads.
- [`services/`](services/) — services implement generation-provider selection, Sigma parsing/compilation, hunting, telemetry, context retrieval, dataset catalogs and risk-scoring orchestration.
- [`__init__.py`](__init__.py) — Python package initialization
- [`main.py`](main.py) — implementation of main

## Interpretation and usage

`main.py` registers HTTP routes; routers should remain thin and domain logic belongs in services. Model assets and local data have separate lifecycle and publication rules.

[Related overview](../README.md)
