# Project documentation

This index separates current platform integration guidance from earlier research design documents. The latter remain available for historical traceability but should not override current validation status.

## Build, deploy and operate

- [Platform architecture](PLATFORM_ARCHITECTURE.md) — detection flow, validation gates and triage paths.
- [Developer setup](DEVELOPER_SETUP.md) — installation, isolated databases and local API/UI startup.
- [Frozen model distribution](MODEL_DISTRIBUTION.md) — separately supplied XGBoost artifact and integrity requirements.
- [Security and privacy](SECURITY_AND_PRIVACY.md) — publication boundaries, credential handling and deployment risks.
- [Validation and limitations](VALIDATION_AND_LIMITATIONS.md) — evidenced results, skipped tests, model-generalization limits and open release gates.

## Requirements and research design

- [Software requirements specification](SRS.md), [business requirements](BRD.md) and [system design](system-design.md).
- [Initial architecture](architecture.md) — historical design view; prefer the platform architecture for the integrated codebase.
- [Project roadmap](PROJECT_ROADMAP.md) and [implementation roadmap](IMPLEMENTATION_ROADMAP.md) — historical planning records rather than real-time completion status.
- [Decision log](DECISION_LOG.md) — design provenance and tradeoffs.

## Data engineering and evidence

- [Data preparation specification](DATA_PREPARATION_SPEC.md) and [data dictionary](DATA_DICTIONARY.md).
- [BOTS v3 Splunk prerequisites](BOTSV3_SPLUNK_REQUIREMENTS.md).
- [Validation snapshot](VALIDATION_SNAPSHOT.md) — stage-specific snapshot; compare with recorded artifacts before citing numbers.

## Earlier coordination documents

[User input checklist](USER_INPUT_CHECKLIST.md) and [next required inputs](NEXT_REQUIRED_INPUTS.md) are retained as historical coordination records, **not** a live release checklist.

Research-grade conclusions belong to the versioned artifacts and frozen evaluation files, not to a UI status badge or a historical TODO list. See the [repository overview](../README.md).
