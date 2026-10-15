# FastAPI backend

The HTTP/API implementation of the threat-hunting research prototype. It includes authentication, ATT&CK context, detection planning and generation, Sigma checking, SIEM/telemetry operations, campaign execution, findings review and optional ML triage.

## Code map

- [`app/main.py`](app/main.py) — FastAPI app initialization and route inclusion.
- [`app/routers/`](app/routers/) — HTTP handlers, authorization and response contracts.
- [`app/services/`](app/services/) — business logic and evidence/ML compatibility gates.
- [`app/core/`](app/core/) — settings, SQLAlchemy and security helpers.
- [`app/schemas/`](app/schemas/) — Pydantic API schemas.
- [`scripts/`](scripts/) — database initialization and data import tools.
- [`tests/`](tests/) — synthetic hunt tests, API regressions and optional model inference tests.

## Local development

From `backend/`, using a dedicated Python virtual environment:

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python scripts/init_db.py
python -m uvicorn app.main:app --reload
```

Set environment variables for your own paths, secrets and external connectors. Schema creation **does not** seed the research evidence or certify demo accounts. See [`docs/DEVELOPER_SETUP.md`](../docs/DEVELOPER_SETUP.md) for fuller instructions and deployment/security caveats.

## ML and provider boundaries

- Sigma drafting may use template, corpus retrieval or a **separately configured** Qwen provider. The actual provider and validation result must be disclosed by each response.
- XGBoost triage requires the verified external **142 MB** model file and GUIDE-compatible features; otherwise the system must report the heuristic path.
- The model's outputs are **advisory**, not automatic TP/FP verdicts or suppression actions.

Run `python -m pytest tests -q` for the backend suite. A skipped ML test indicates that model-dependent inference was **not** exercised. No local model training is required to run the API.
