# Detection engineering pipeline

Scripts coordinating technique prioritization, hypothesis routing, eligibility, grounded plans and Sigma generation/validation.

## Contents
- [`detection_eligibility/`](detection_eligibility/) — builds and audits the eligibility decisions used to constrain which hypothesis/detection paths may advance.
- [`detection_plan/`](detection_plan/) — creates retrieval contexts, baseline dispatches and assembled detection plans suitable for later Sigma synthesis.
- [`hypothesis_engine/`](hypothesis_engine/) — dispatch and validation of distinct hypothesis families with versioned schemas and batch execution tools.
- [`sigma/`](sigma/) — scripts for baseline generation design, rule drafting and pySigma validation.
- [`build_detection_gap_proxy.py`](build_detection_gap_proxy.py) — implementation of build detection gap proxy
- [`build_hypothesis_context.py`](build_hypothesis_context.py) — implementation of build hypothesis context
- [`build_hypothesis_context_all.py`](build_hypothesis_context_all.py) — implementation of build hypothesis context all
- [`build_hypothesis_router_v1.py`](build_hypothesis_router_v1.py) — implementation of build hypothesis router v1
- [`build_platform_eligibility.py`](build_platform_eligibility.py) — implementation of build platform eligibility
- [`build_sigma_detection_coverage.py`](build_sigma_detection_coverage.py) — implementation of build sigma detection coverage
- **Additional tracked files:** 5 (see directory listing for complete inventory).

## Interpretation and usage

Stages should preserve ATT&CK and telemetry provenance; invalid or ungrounded plans are blocked before executable searches.

[Related overview](../../README.md)
