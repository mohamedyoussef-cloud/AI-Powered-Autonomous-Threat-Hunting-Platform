# Platform architecture

## Scope

This repository contains an academic autonomous threat-hunting research pipeline and a product-oriented analyst interface. The two should not be conflated: recorded offline experiments are not proof of live deployment.

## Conceptual workflow

1. Evaluate ATT&CK-grounded hypotheses and available telemetry.
2. Produce detection plans and candidate Sigma rules.
3. Validate rule structure, field compatibility and execution eligibility.
4. Compile eligible rules for an appropriate SIEM/backend and execute against configured telemetry.
5. Separate execution hits from validated hunt findings.
6. Route supported findings through analyst-assisted ML triage, preserving the ability to review or override suggestions.

## Components

- **Research pipeline:** `src/`, `scripts/`, `configs/`, `schemas/`, `artifacts/`, and `evaluation/`.
- **Backend:** FastAPI services and routers under `backend/app/`.
- **Frontend:** React/Vite application under `frontend/`.
- **LLM:** Optional configurable generation provider; model execution requires separate compatible infrastructure. Deterministic template and corpus options must be labeled by source.
- **ML:** Frozen XGBoost triage model plus preprocessing contracts; model loading is optional and must be reported explicitly. Fallback inference is not XGBoost inference.
- **Runtime:** Local telemetry or an explicitly configured SIEM connector. Offline validation results do not imply a connected SIEM.

## Integration boundaries

Read-only research outputs, source metadata, runtime telemetry, model inference and analyst verdicts have different provenance. The backend must not treat absent sources as ingested, unvalidated rules as executable, or raw search results as confirmed security incidents.

## Deployment status

The repository is a research-backed, product-oriented software platform. The codebase requires deployment-specific configuration and independent hardening before any exposed or production environment.
