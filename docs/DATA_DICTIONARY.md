# Canonical Data Dictionary

## Lineage fields

| Field | Type | Meaning |
|---|---|---|
| `source_dataset` | string | Registered source name. |
| `source_record_id` | string | Stable identifier in or derived from the source. |
| `source_file` | nullable string | Original file, object, or index reference. |
| `schema_version` | string | Canonical schema version used. |
| `pipeline_version` | string | Transformation pipeline version. |
| `ingested_at` | UTC datetime | Time the source record entered the pipeline. |

## Core telemetry fields

| Field | Type | Meaning |
|---|---|---|
| `event_uid` | string | Globally unique canonical event identifier. |
| `timestamp` | UTC datetime | Canonical event time. |
| `event.id` | nullable string | Source event identifier such as Windows Event ID. |
| `event.category` | enum | High-level telemetry domain. |
| `event.action` | string | Normalized action within the domain. |
| `event.provider` | nullable string | Provider or product that emitted the event. |
| `event.dataset` | nullable string | Source dataset/sourcetype/channel designation. |
| `host.id` | nullable string | Resolved host entity ID. |
| `host.name` | nullable string | Normalized host name. |
| `user.id` | nullable string | Resolved user entity ID. |
| `user.name` | nullable string | Normalized account name. |
| `process.executable` | nullable string | Full executable path. |
| `process.command_line` | nullable string | Full observed command line. |
| `source.ip` | nullable IP | Source address when relevant. |
| `destination.ip` | nullable IP | Destination address when relevant. |
| `raw` | object/string/null | Original source payload or safe raw representation. |

## Finding fields

| Field | Type | Meaning |
|---|---|---|
| `finding_id` | string | Unique finding identifier. |
| `finding_type` | enum | Behavioral family used for aggregation and modeling. |
| `rule_ids` | array | Detection rules contributing to the finding. |
| `technique_ids` | array | ATT&CK mappings. |
| `first_seen` | UTC datetime | Beginning of evidence window. |
| `last_seen` | UTC datetime | End of evidence window. |
| `event_count` | integer | Number of linked evidence events. |
| `evidence_event_ids` | array | Exact canonical event IDs. |
| `aggregation_policy_id` | string | Versioned grouping policy. |
| `label.value` | enum | Ground-truth or review state. |
| `label.source` | enum | Origin of the label. |
| `label.confidence` | 0-1 number | Label confidence. |

## Feature rules

- Identifiers, raw strings, rule IDs, dataset names, and source file names are metadata unless explicitly encoded through a reviewed transformation.
- A missing numeric feature is not automatically zero.
- When imputation is used, a missingness indicator must be considered.
- Feature definitions must include observation window, aggregation function, and leakage constraints.
