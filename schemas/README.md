# Canonical research schemas

JSON Schema contracts for ATT&CK techniques, normalized events, findings, Sigma records and feature vectors.

## Contents
- [`phase3/`](phase3/) — versioned schema definitions for hypothesis outputs, eligibility decisions and detection plans.
- [`canonical_event.schema.json`](canonical_event.schema.json) — structured canonical event.schema records
- [`hunt_finding.schema.json`](hunt_finding.schema.json) — structured hunt finding.schema records
- [`finding_feature_record.schema.json`](finding_feature_record.schema.json) — structured finding feature record.schema records
- **Additional tracked files:** 2 (see directory listing for complete inventory).

## Interpretation and usage

These schemas govern research data interchange. Backend HTTP contracts are separately represented by Pydantic models under `backend/app/schemas/`.

[Related overview](../docs/README.md)
