# Runtime execution results

Per-query search outcomes, errors and manifest for the recorded Splunk runtime batch.

## Contents
- [`summary_v1.json`](summary_v1.json) — recorded aggregate outcomes
- [`runtime_execution_results_v1.jsonl`](runtime_execution_results_v1.jsonl) — per-hunt execution result records
- [`runtime_execution_errors_v1.jsonl`](runtime_execution_errors_v1.jsonl) — captured execution errors
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

Inspect individual result and error records together with `summary_v1.json`; 22 nonzero raw-result hunts are not 22 confirmed detections.

[Related overview](../../../README.md)
