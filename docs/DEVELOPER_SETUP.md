# Developer setup

## Prerequisites

Python and pip, Node.js and npm, Git, and sufficient disk space for chosen dependencies. An external GPU is **not** required for the REST API, interface, or standard regression tests. GPU-hosted LLM inference is optional and configured separately.

## Backend (PowerShell)

From the repository root:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Review `.env` for local-only values. Never commit it. For a clean local SQLite database, use `DATABASE_URL=sqlite:///./app/data/threathunt_v3.db` and run:

```powershell
.\.venv\Scripts\python.exe scripts/init_db.py
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

API documentation is available at `/docs`. Data catalogs can display un-ingested/unavailable statuses without raw datasets. The database initialization script creates schema, **not** research data or production accounts. The current auth implementation seeds demo accounts; do not expose the service to a network before removing or disabling that behavior and provisioning real users.

## Frontend

In another terminal, from `frontend/`:

```powershell
npm ci
npm run dev
```

For a production-style build run `npm run build`. Vite outputs can be packaged with the backend only as part of a controlled release build. Do not version `node_modules` or temporary frontend build output.

## Verification

In `backend/` run:

```powershell
python -m pytest tests -q
```

ML-specific tests may be marked skipped when the external model file has not been installed. A skip is **not** evidence that model inference ran. Refer to `MODEL_DISTRIBUTION.md` and `VALIDATION_AND_LIMITATIONS.md`.
