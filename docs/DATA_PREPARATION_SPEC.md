# Data Preparation and Unification Specification

## 1. Objective

Create a reproducible, auditable data layer that supports the full platform workflow:

1. Environment Profile.
2. ATT&CK Technique Filtering.
3. Technique Scoring and Ranking.
4. Explainable Hunt Hypothesis.
5. Mistral Detection Synthesis.
6. Sigma Validation.
7. Query Execution.
8. Hunt Findings.
9. ML triage and reporting.

## 2. Non-negotiable design rules

- Raw data is immutable.
- Every transformed record has complete lineage.
- ATT&CK, Sigma, telemetry, findings, and ML features remain separate canonical models.
- Field unification is semantic: equivalent source fields map to one canonical field.
- Missing fields remain missing. The pipeline does not invent values.
- ML feature vectors are unified only among findings evaluated by the same model or feature contract.
- BOTS v3 does not provide a reliable malicious/benign label for every event.
- EVTX-ATTACK-SAMPLES is attack-oriented and cannot independently represent benign enterprise behavior.
- LLM supervised data is grounded in validated Sigma rules and ATT&CK context.

## 3. Storage zones

### Raw
Original files, checksums, versions, and manifests. Never modified.

### Interim
Parsed source-native records and profiling outputs. These may retain source-specific names.

### Processed
Canonical records that pass schema and quality validation.

### Quarantine
Records that fail parsing, schema validation, referential integrity, or conflict checks. Every rejected record includes a reason.

## 4. Canonical models

### 4.1 Knowledge
ATT&CK techniques, sub-techniques, tactics, platforms, data components, detection strategies, analytics, and relationships.

### 4.2 Detection
Sigma metadata, logsource, detection logic, condition, fields, modifiers, ATT&CK tags, validation state, compilation state, duplicate group, and split group.

### 4.3 Telemetry
A common event envelope plus optional domain objects for process, authentication, network, file, registry, cloud, email, and endpoint-security data.

### 4.4 Entity
Stable IDs and aliases for hosts, users, processes, IPs, cloud accounts, resources, and applications.

### 4.5 Finding
Aggregated evidence produced by validated detections. Findings reference their exact evidence events and aggregation policy.

### 4.6 ML feature record
A fixed feature contract for each finding family. Global features are shared; domain features differ by process, authentication, network, file, registry, cloud, or cross-domain case.

## 5. Field unification policy

A canonical field is created only when source fields have equivalent semantics. For example:

- Sysmon `Image`, Security 4688 `NewProcessName`, and Splunk CIM `process_path` map to `process.executable`.
- Sysmon `CommandLine`, Security 4688 `ProcessCommandLine`, and Splunk CIM `process` map to `process.command_line`.
- EVTX `Computer`, Splunk `host`, and CIM `dest` may map to `host.name` after source-specific validation.

A network event is not required to have process fields. A process event is not required to have cloud fields. Optional domain objects remain null when unavailable.

## 6. ML feature unification policy

The complete project should use a family of feature contracts, not one universal flat feature table.

### Shared global features

- event count
- duration
- unique hosts
- unique users
- unique sources
- rule count
- technique count
- event rate
- after-hours ratio
- asset criticality
- technique priority

### Process-specific features

- command-line length and entropy
- encoded-command indicator
- suspicious-argument count
- process/path rarity
- parent-child rarity
- temporary-directory execution
- system-directory execution

### Authentication-specific features

- failed-login count
- success after failures
- unique source IPs
- new-device indicator
- privileged-account indicator

### Network-specific features

- unique destinations
- rare-port ratio
- inbound/outbound bytes
- external-destination ratio
- periodicity or beaconing score

Models may share a global feature layer, but domain-specific models or feature branches are expected when behaviors differ materially.

## 7. Label policy

Allowed labels:

- malicious
- benign
- suspicious
- requires_review
- unknown

Every label stores its source, confidence, reviewer, and evidence. Source dataset identity is traceability metadata and must not be used as a model predictor.

## 8. Leakage controls

- Group near-duplicate Sigma rules before train/validation/test splitting.
- Do not split multiple variants of one rule family across train and test.
- Compute behavioral baselines using data available before the finding observation cutoff.
- Exclude analyst disposition fields and future events from model features.
- Exclude source dataset name from predictive features.

## 9. Output contracts

The JSON schemas in `/schemas` are the first executable contracts. Schema changes require semantic versioning and a migration note.
