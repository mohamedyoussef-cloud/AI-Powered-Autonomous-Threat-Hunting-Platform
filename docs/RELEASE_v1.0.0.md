# v1.0.0 — Research prototype release

**Scope:** FastAPI + React threat-hunting research platform, evidence-gated Sigma/SPL
generation and execution, plus optional Qwen provider and analyst-assisted XGBoost triage.
Not a production-certified autonomous SOC system.

## Validated at release preparation

- GitHub Basic CI and Frontend Build: 2/2 successful on the prior integration commit;
  verify both again on the *release* commit before tagging.
- Local backend test suite: 24 passed, 3 skipped.
- Frozen-model tests: 8 passed using a complete local ML runtime bundle.
- FastAPI + React assets + real XGBoost API integration smoke: passed; 16 runtime
  asset hashes and 103 model features verified; verdict leakage gate passed.
- Analyst-assisted only. Never auto-close or suppress incidents based on ML scores.
- Research evidence includes 540 pySigma-validated rules and 404 executed hunts;
  no validated true-positive operational findings are claimed.

## Model and artifact distribution

The model is NOT tracked in Git and is NOT included in a standard clone.
Verified private candidate: `ml_triage_runtime_candidate_v1.zip` (59.04 MiB).
SHA-256: `ebb00bf6d2a708fa80a3bf3d3125050b8355ee61f588fe546ed7ed2135b3df80`.
The frozen model was not retrained or modified. The runtime ZIP contains 16 original
assets and a separately generated deployment manifest. Original 32-file research
provenance and results remain intact in the private handoff.

Microsoft describes GUIDE as licensed under CDLA-Permissive-2.0 in its research paper:
https://arxiv.org/html/2407.09017
License details: https://cdla.dev/permissive-2-0/
Before public upload of the model archive, finish a **human review of the two Joblib
files and training-derived mapping keys** and include any applicable license notice.
Do not upload source_reference, organization split maps, internal path manifests, or
the original unrestricted research handoff. This Release may initially ship
source code without a public model binary.

## Deployment boundary

Production mode fails closed without strong auth configuration. Development mode
contains known demo accounts and must be bound only to a trusted loopback address.
See `docs/SECURITY_AND_PRIVACY.md` and `docs/DEVELOPER_SETUP.md`. Validate real SIEM
permissions and telemetry availability independently. The React build artifact is
published by GitHub Actions, not committed under `backend/static`.

## Remaining limitations

- 3 backend tests intentionally skipped; their functionality is not established by
  those test results.
- CI validates import/build, not full SIEM integration.
- XGBoost GUIDE-trained features may be absent in Sigma/EVTX findings; in that case
  the system must report heuristic triage rather than a model inference.
- Public historic Git commits still contain previously tracked GUIDE-derived metadata.
