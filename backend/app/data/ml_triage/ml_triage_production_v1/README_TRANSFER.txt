ML TRIAGE PRODUCTION TRANSFER BUNDLE v1
=========================================

Model:
  xgboost_te_v3_1

Final evaluation:
  Frozen Test completed.
  No further model tuning is permitted.

Deployment mode:
  Analyst-assisted triage.

Allowed:
  - 3-class prediction
  - TP/BP/FP probabilities
  - prioritization recommendation
  - review queue recommendation
  - analyst decision support

Not allowed in Product v1:
  - autonomous final verdict
  - automatic false-positive suppression
  - automatic benign closure
  - autonomous escalation

Classes:
  0 = TRUE_POSITIVE
  1 = BENIGN_POSITIVE
  2 = FALSE_POSITIVE

Operational state:
  NEEDS_REVIEW is NOT a fourth model class.

Important:
  This bundle contains model/runtime artifacts only.
  It does NOT contain GUIDE raw training data or
  intermediate training datasets.

Local integration must preserve:
  - exact feature preprocessing
  - train-only frequency maps
  - target encoding mappings
  - categorical unknown-to-missing behavior
  - feature order
  - row-normalized native probabilities
  - locked class multipliers
