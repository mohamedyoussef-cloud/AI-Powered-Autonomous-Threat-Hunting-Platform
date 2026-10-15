# Hunt execution scheduling

Recorded execution queue, deferred workloads, summary and runtime result bundle.

## Contents
- [`runtime_results_v1/`](runtime_results_v1/) — per-query search outcomes, errors and manifest for the recorded Splunk runtime batch.
- [`summary_v1.json`](summary_v1.json) — recorded aggregate outcomes
- [`runtime_execution_queue_v1.jsonl`](runtime_execution_queue_v1.jsonl) — searches scheduled for runtime
- [`runtime_execution_deferred_v1.jsonl`](runtime_execution_deferred_v1.jsonl) — deferred execution candidates
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

The recorded study executed 404 ready hunts. Some queries were deferred for execution-readiness reasons; neither successful execution nor nonzero hits alone establish a validated threat.

[Related overview](../../README.md)
