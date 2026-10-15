# Validation evidence and limitations

## Evidence already present in the project

The repository preserves 540 generated Sigma rules, supporting validation artifacts, compiled SPL queries and runtime evidence. Actual search hits, hunt findings and confirmed positives have different evidentiary meanings; see `artifacts/splunk/` for the underlying records.

## Recorded ML study

The frozen three-class GUIDE evaluation supports **analyst-assisted triage** and shows reduced transfer performance on previously unseen organizations. Do not present this classifier as a fully autonomous verdict engine. Training and offline evaluation metrics must always be attributed to their actual split and artifact version.

## Software test interpretation

- Endpoint and regression tests are not equivalent to a full external-SIEM deployment test.
- A suite reporting skipped ML tests has **not** exercised the missing external model.
- Synthetic SQLite fixtures are intentionally independent of real databases or live credentials.
- The Qwen generation provider is optional; corpus retrieval and deterministic template generation must carry their own provenance and explicit validation states.
- `not_configured`, `not_ingested`, and `unavailable` must never be silently relabeled as success.

## Open release gates

Before claiming an operational release, validate a fresh checkout, frontend build, API routes, environment-specific secret management, clean-database provisioning, external artifact loading, and the SIEM integration actually configured. Production deployment also requires account bootstrapping and security hardening of demonstration authentication defaults.
