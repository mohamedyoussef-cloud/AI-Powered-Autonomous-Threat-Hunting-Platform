# Pipeline scripts

Offline reproducibility and maintenance scripts; execution may require datasets or tooling not included in a Git clone.

## Contents

Subdirectories:

- `llm/`

Files in this directory:

- `analyze_runtime_keyword_contribution.py`
- `audit_evtx_direct_parse_29.py`
- `audit_evtx_full_v0_4_mapping.py`
- `audit_integrated_telemetry_evidence.py`
- `bootstrap_check.py`
- `build_botsv3_canonical_mapping.py`
- `build_botsv3_master_profile.py`
- `build_botsv3_telemetry_capability.py`
- `build_coverage_report.py`
- `build_data_preparation_release_v1.py`
- `build_evtx_full_v0_4_candidate.py`
- `build_integrated_telemetry_evidence.py`
- `build_llm_dataset_splits_v1.py`
- `build_llm_training_corpus_v1.py`
- `build_splunk_runtime_execution_queue.py`
- `build_telemetry_evidence_gate.py`
- `build_validated_hunt_findings.py`
- `compile_sigma_to_spl_production.py`
- `create_source_manifest.py`
- `finalize_botsv3_canonical_mapping.py`

Additional files are discoverable through `git ls-files` at the repository root.

## Provenance and maintenance

Do not add secrets, raw private datasets, cached runtime databases, or unverified performance claims. Keep versioned evidence distinct from generated build output.
