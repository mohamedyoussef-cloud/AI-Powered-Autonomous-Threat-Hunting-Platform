# Backend

FastAPI backend for the Core Threat Hunting MVP.

## Current MVP Responsibility

The first backend increment should support:

- Threat hunt campaign CRUD
- Campaign objective, owner, status, and risk level
- MITRE ATT&CK tactic/technique mapping storage
- Hypothesis planning records
- Analyst notes and status history
- Manager review status

## Later Expansion

After the Core Threat Hunting MVP is stable, the backend can be extended with:

- Query generation orchestration
- Simulated SIEM query runner
- ML classification calls
- Case management
- Hunt report generation

## Run Locally

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```
