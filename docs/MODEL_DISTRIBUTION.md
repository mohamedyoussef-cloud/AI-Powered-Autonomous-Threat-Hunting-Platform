# Frozen ML model distribution

## Model artifact

The integrated backend expects the frozen `xgboost_te_v3_1.json` under:

`backend/app/data/ml_triage/ml_triage_production_v1/model/`

This approximately 142 MB artifact exceeds GitHub's normal 100 MB per-file limit and is intentionally absent from regular Git history. The *model is not downloaded automatically by a clone*.

## Release process

1. Use the original frozen, verified distribution package; **do not retrain or alter the model**.
2. Publish the model as an explicitly versioned GitHub Release asset or a separately controlled artifact with documented redistribution permission.
3. Record the genuine SHA-256 of the distributed asset in the release metadata; never substitute an unverified checksum.
4. Extract/install using the existing directory structure so the model and related preprocessing contracts remain together.
5. Verify the artifact and manifest consistency before enabling ML inference.
6. Run `backend/tests/test_ml_triage.py`; distinguish successful inference from skipped tests.

The repository contains preprocessing, evaluation and policy metadata but may intentionally exclude provenance files containing workstation or GPU-infrastructure paths. Original locked artifacts remain the source of truth for the research evaluation. Do not modify frozen manifests or evaluation outputs to silence packaging errors; produce a separate deployment manifest when necessary.

## Safety policy

The GUIDE-trained model is approved only for **analyst-assisted** triage. Classification probabilities and queue priority recommendations are advisory. No unattended FP suppression, incident closure, or TP verdict generation is authorized. If the incoming SIEM finding lacks model-compatible features, the application must explicitly report an alternate/heuristic path rather than claiming XGBoost inference.
