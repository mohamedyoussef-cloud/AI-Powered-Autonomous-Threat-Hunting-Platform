# Research and operational configuration

Phase 3 policies, ingestion contexts and logical telemetry source selection files.

## Contents
- [`ingestion/`](ingestion/) — reference environment and evidence-policy inputs used to describe data acquisition and source applicability.
- [`phase3/`](phase3/) — versioned routing, evidence-signature, environment-profile and prioritization policies for detection construction.
- [`telemetry/`](telemetry/) — versioned source-identity and capability registry policies used during telemetry matching.

## Interpretation and usage

This directory is not interchangeable with `configs/`: the latter hosts the primary dataset registry and pipeline-level contracts. Private local paths and tokens do not belong in tracked configuration.

[Related overview](../docs/README.md)
