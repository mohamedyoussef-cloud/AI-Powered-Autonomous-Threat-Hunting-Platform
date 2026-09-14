# Full-Project Data Preparation Roadmap

## Workstream A - Governance and source registration

- Freeze source versions.
- Compute checksums.
- Record licenses and provenance.
- Create source manifests.

## Workstream B - ATT&CK ingestion

- Parse Enterprise STIX 2.1.
- Resolve techniques, sub-techniques, tactics, platforms, data components, detection strategies, analytics, and relationships.
- Separate revoked/deprecated objects.
- Produce coverage-ready tables.

## Workstream C - Sigma ingestion

- Parse YAML safely.
- Validate Sigma structure.
- Extract detection fields and modifiers.
- Resolve ATT&CK tags.
- Detect exact and near duplicates.
- Compile with approved pySigma backends and processing pipelines.
- Build RAG documents and grouped LLM training splits.

## Workstream D - BOTS v3 preparation

- Register the pre-indexed dataset and Splunk metadata.
- Profile indexes, sourcetypes, time ranges, fields, null rates, and cardinalities.
- Map source fields to canonical fields.
- Build scenario/case ground-truth references without inventing event labels.

## Workstream E - EVTX preparation

- Inventory files and technique-folder mappings.
- Parse event XML.
- Normalize Windows fields by provider/Event ID.
- Preserve raw XML and parse errors.
- Build positive detection validation sets.

## Workstream F - Entity resolution and enrichment

- Resolve host/user/process/account aliases.
- Add environment profile, asset criticality, business hours, and allowlist context.
- Track enrichment source and confidence.

## Workstream G - Finding and label construction

- Define aggregation policies by behavioral family.
- Link exact evidence events.
- Build label registry and analyst-review workflow.

## Workstream H - ML data products

- Define global and domain feature contracts.
- Implement leakage-safe historical baselines.
- Build grouped, time-aware training and evaluation splits.

## Workstream I - LLM/RAG data products

- Create source-grounded Sigma instruction pairs.
- Mark template-generated/synthetic context explicitly.
- Build retrieval documents with technique, logsource, fields, and validation metadata.

## Workstream J - Quality, lineage, and release

- Automate schema validation and quality reports.
- Version all data products.
- Generate dataset cards and release manifests.
