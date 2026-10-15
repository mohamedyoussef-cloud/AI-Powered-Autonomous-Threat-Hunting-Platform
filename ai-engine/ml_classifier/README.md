# ML triage — design boundary

Historical placeholder for the classifier subsystem; it does not contain trained weights or an independently runnable classifier.

## Contents
- No executable or data files are tracked in this folder at this snapshot.

## Interpretation and usage

The implemented three-class GUIDE-trained XGBoost inference adapter is `backend/app/services/ml_triage.py`. ML predictions are advisory and gated on feature compatibility; insufficiently compatible hunt findings use an explicitly identified heuristic fallback.

[Related overview](../../docs/README.md)
