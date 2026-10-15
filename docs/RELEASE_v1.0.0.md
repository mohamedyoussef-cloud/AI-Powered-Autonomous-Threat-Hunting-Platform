# AI-Powered Autonomous Threat Hunting Platform — v1.0.0

**Release status:** Integrated platform release · Core implementation complete · Local and CI validation passed · **Live-stream telemetry validation pending**

This release delivers the integrated FastAPI and React threat-hunting platform, bringing together ATT&CK-grounded hypothesis generation, detection eligibility and planning, Sigma rule generation and validation, Splunk SPL compilation, hunt execution, evidence-aware findings, and an analyst-facing interface. It supports an optional Qwen3-8B detection-generation provider and analyst-assisted XGBoost triage.

The platform is **ready for controlled deployment and live-telemetry acceptance testing**. The implemented and tested workflows are available now; the remaining operational validation is to exercise them against authorized, continuously arriving SIEM telemetry. This release does not present untested live-stream detection accuracy or operational readiness as established results.

## Verification completed

- **GitHub Actions:** Basic CI and Frontend Build both succeeded (**2/2**) for commit `0a802d1`, the commit tagged `v1.0.0`.
- **Backend:** 24 tests passed; 3 were skipped and are not counted as validated.
- **XGBoost:** 8 tests passed with the unchanged frozen model and full local runtime dependencies.
- **End-to-end integration smoke:** FastAPI health, compiled React page and JavaScript assets, frozen-model loading, live API inference, and the analyst-verdict leakage gate all passed. The 16 packaged runtime assets passed SHA-256 verification; the model uses 103 features.
- **Research execution evidence:** 540 Sigma rules generated with validation and compilation artifacts, and 404 recorded hunt executions. These counts measure engineering and execution stages—not 540 confirmed detections or 404 proven incidents. No independently validated operational true-positive findings are claimed.
- **Analyst safety:** XGBoost scores support analyst triage only. Insufficient GUIDE-compatible fields must yield an explicitly identified heuristic fallback rather than an asserted model prediction. No automatic incident closure or suppression is claimed.

## Model availability and reproducibility

The source repository does not include the frozen model weights or complete runtime package. A locally verified runtime package is prepared but has not yet been attached publicly:

- `ml_triage_runtime_candidate_v1.zip` — **59.04 MiB**
- SHA-256: `ebb00bf6d2a708fa80a3bf3d3125050b8355ee61f588fe546ed7ed2135b3df80`
- Contents: 16 original, integrity-checked runtime assets and a separate deployment manifest.

The model was **not retrained or modified**. Public attachment remains subject to final content review of serialized Joblib assets, training-derived mapping keys, and appropriate attribution. The original source-reference files, organization split maps, internal-path manifests, and unrestricted research handoff are not public release assets. The [Microsoft GUIDE paper](https://arxiv.org/html/2407.09017) describes the dataset as CDLA-Permissive-2.0; see the [license text](https://cdla.dev/permissive-2-0/).

## Deployment and next validation stage

Authentication requires explicit secure production configuration; local development accounts are not intended for public exposure. The React distribution is produced through GitHub Actions, while SIEM connectors and optional Qwen inference require environment-specific configuration.

**Pending live-stream acceptance:** Connect to an authorized SIEM with continuous telemetry, check field coverage and detection routing, validate end-to-end event-to-finding behavior, measure false positives and processing latency, and review permissions and operational monitoring. These are acceptance activities, not missing core implementation claims.

Historical Git commits may still contain GUIDE-derived metadata removed from the current branch; publication-history remediation, if required, is separate from this release.

**Documentation:** [Architecture](https://github.com/mohamedyoussef-cloud/AI-Powered-Autonomous-Threat-Hunting-Platform/blob/main/docs/PLATFORM_ARCHITECTURE.md) · [Developer setup](https://github.com/mohamedyoussef-cloud/AI-Powered-Autonomous-Threat-Hunting-Platform/blob/main/docs/DEVELOPER_SETUP.md) · [Security and privacy](https://github.com/mohamedyoussef-cloud/AI-Powered-Autonomous-Threat-Hunting-Platform/blob/main/docs/SECURITY_AND_PRIVACY.md) · [Validation scope](https://github.com/mohamedyoussef-cloud/AI-Powered-Autonomous-Threat-Hunting-Platform/blob/main/docs/VALIDATION_AND_LIMITATIONS.md)
