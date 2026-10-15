# Frozen GUIDE XGBoost triage bundle

This directory contains the deployment **metadata and preprocessing assets** for the frozen `XGBoost TE v3.1` classifier. It is intentionally not a complete stand-alone inference package in a normal Git clone.

## Included source tree

- [`ml_triage_production_v1/evaluation/`](ml_triage_production_v1/evaluation/) — locked validation/frozen-test and experiment summaries.
- [`ml_triage_production_v1/policy/`](ml_triage_production_v1/policy/) — analyst-assisted deployment and runtime constraints.
- [`ml_triage_production_v1/preprocessing/`](ml_triage_production_v1/preprocessing/) — feature schema and target-encoding mappings.
- [`ml_triage_production_v1/model/`](ml_triage_production_v1/model/) — model contract; frozen `xgboost_te_v3_1.json` is omitted from Git.
- [`ml_triage_production_v1/provenance/`](ml_triage_production_v1/provenance/) — public evaluation provenance retained where appropriate.

## Release blockers

The frozen model JSON is approximately **142 MB**, so model distribution is separate from Git. Some original manifest/provenance records include environment-specific paths and are intentionally omitted from this snapshot. **Do not fabricate hashes or change frozen evidence.** Any published model package needs an integrity-checked, self-consistent manifest and legal redistribution clearance.

The GUIDE alert model's frozen organization-disjoint macro-F1 is approximately **0.4523**. It is approved for **analyst-assisted triage only**. Sigma/EVTX hunt findings commonly fail its feature-coverage gate, requiring a clearly labeled heuristic route rather than pretend XGBoost predictions.

See [model distribution](../../../../docs/MODEL_DISTRIBUTION.md) and [validation limitations](../../../../docs/VALIDATION_AND_LIMITATIONS.md).
