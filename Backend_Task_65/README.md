# Task 65: Backend Architecture and API Design

## Overview
The backend server that connects all platform components in one pipeline.

## Pipeline
Hypothesis → LLM → Sigma → SPL → Validation → Splunk → Findings → ML → Analyst

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/health | Health check |
| POST | /api/hunt/start | Start new hunt |
| GET | /api/hunt/{id}/status | Get hunt status |
| GET | /api/hunt/{id}/findings | Get findings |
| POST | /api/findings/{id}/verdict | Submit verdict |
| GET | /api/hunts | List all hunts |
| GET | /api/report/{id} | Generate report |

## Services
| Service | Input | Output | Status |
|---------|-------|--------|--------|
| HypothesisService | hypothesis | sigma_rule | ✅ Ready |
| SPLService | sigma_rule | spl_query | ✅ Ready |
| SplunkService | spl_query | findings | ⏳ Awaiting Splunk |
| TriageService | findings | triage_label | ✅ Ready |
| ReportService | hunt_id | HuntReport | ⏳ Pending |

## Database Tables
| Table | Description |
|-------|-------------|
| hunts | One row per hunt job |
| findings | One row per Splunk result |
| verdicts | Analyst feedback |

## Tech Stack
| Component | Technology |
|-----------|------------|
| Framework | FastAPI |
| Database | SQLite |
| API Style | REST |

## Files
| File | Description |
|------|-------------|
| task65_architecture.py | Architecture design + DB init |
| app.py | FastAPI backend server |
| task65_results.json | Architecture design output |
| threat_hunting.db | SQLite database |

## How to Run
    pip install fastapi uvicorn pydantic
    python task65_architecture.py
    python app.py

## Results
| Metric | Value |
|--------|-------|
| API Endpoints | 7 ✅ |
| Services | 5 ✅ |
| DB Tables | 3 ✅ |
| Status | COMPLETE ✅ |