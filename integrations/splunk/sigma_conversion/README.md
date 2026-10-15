# Historical Sigma-to-SPL conversion experiment

This folder preserves an **earlier pySigma/Splunk conversion run** over **394 candidate rules**; it is distinct from the later **540-rule compilation** recorded under `artifacts/splunk/compilation/`.

## Files

- [`sigma_to_splunk.py`](sigma_to_splunk.py) — experiment conversion script.
- [`spl_conversion_results.json`](spl_conversion_results.json) — archived conversion outcomes.
- [`eval_results.json`](eval_results.json) — original input/evaluation records.

## Validity boundary

Older scripts may perform automatic repairs to malformed Sigma. Replacing missing conditions or inserting placeholder events is not equivalent to an evidence-grounded, analyst-approved detection. Do not label converted SPL as execution-ready without source resolution, validation gates and live permissions.

For the authoritative recorded compilation and runtime evidence, see [`artifacts/splunk/`](../../../artifacts/splunk/) and [validation limitations](../../../docs/VALIDATION_AND_LIMITATIONS.md).
