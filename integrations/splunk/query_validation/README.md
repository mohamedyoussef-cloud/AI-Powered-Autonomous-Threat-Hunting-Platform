# Historical SPL query-screening experiment

This directory contains a lightweight pre-execution filter from an **earlier 394-query study**. It is not the complete authorization model for a production Splunk connector.

## Reproducing the archived screening

- [`validation_gate.py`](validation_gate.py) — experimental input-length, keyword and command screening.
- [`validation_results.json`](validation_results.json) — recorded judgments from the legacy query batch.

The saved batch is a separate experimental population from the later **540-rule Sigma/SPL compilation** and **404-hunt runtime execution**. Do not present the legacy batch pass rate as a guarantee that every SPL search is safe, telemetry-ready or correctly scoped.

## Operational boundary

The integrated backend uses additional rule, execution and telemetry controls. Production queries still require read-only SIEM permissions, input validation, source-specific authorization, logging and analyst review. See [`artifacts/splunk/`](../../../artifacts/splunk/) for the recorded research pipeline.
