# Reproducibility and research build scripts

Versioned offline programs for ATT&CK/telemetry preparation, LLM dataset construction, Sigma validation, SPL compilation and hunt evidence aggregation.

## Contents
- [`llm/`](llm/) — training and evaluation procedures for research Sigma generation, plus telemetry-resolver experiments.
- [`analyze_runtime_keyword_contribution.py`](analyze_runtime_keyword_contribution.py) — implementation of analyze runtime keyword contribution
- [`audit_evtx_direct_parse_29.py`](audit_evtx_direct_parse_29.py) — implementation of audit evtx direct parse 29
- [`audit_evtx_full_v0_4_mapping.py`](audit_evtx_full_v0_4_mapping.py) — implementation of audit evtx full v0 4 mapping
- [`audit_integrated_telemetry_evidence.py`](audit_integrated_telemetry_evidence.py) — implementation of audit integrated telemetry evidence
- [`bootstrap_check.py`](bootstrap_check.py) — implementation of bootstrap check
- [`build_botsv3_canonical_mapping.py`](build_botsv3_canonical_mapping.py) — implementation of build botsv3 canonical mapping
- **Additional tracked files:** 30 (see directory listing for complete inventory).

## Interpretation and usage

Execution may require separately obtained datasets, configured infrastructure and substantial compute. Do not rerun full research evaluations just to operate the web app; see the release artifacts and backend setup guide.

[Related overview](../docs/README.md)
