# Event field mappings

Security logs often describe the same activity using different field names. For example, a process executable may appear as `Image` in Sysmon, `NewProcessName` in a Windows Security 4688 event, or `process_path` in Splunk CIM data. The mapping files in this directory keep those source-specific names in one place.

They are used to support consistent event records while retaining the original telemetry for review and troubleshooting.

## Files in this directory

| File | Purpose |
| --- | --- |
| [`field_mapping.yaml`](field_mapping.yaml) | Cross-source field definitions for Windows event logs, Sysmon, Splunk CIM, and Elastic ECS. It also records expected types and selected transformations. |
| [`evtx_samples_csv_field_mapping.yaml`](evtx_samples_csv_field_mapping.yaml) | Field candidates for the parsed EVTX-ATTACK-SAMPLES CSV dataset. The preparation code checks candidate columns in order and uses the first non-empty value. |
| [`event_taxonomy.yaml`](event_taxonomy.yaml) | Reference categories and action names for activities such as process execution, logons, network connections, and registry changes. |
| [`value_normalization.yaml`](value_normalization.yaml) | Normalization policies for timestamps, strings, Windows paths, account names, IP addresses, and missing values. |

## Mapping an event

Consider the executable path for a process creation event:

- Sysmon Event ID 1: `Image`
- Windows Security Event ID 4688: `NewProcessName`
- Splunk CIM: `process_path`
- Elastic ECS: `process.executable`

These fields are listed under `process.executable` in [`field_mapping.yaml`](field_mapping.yaml). Their values still need to be interpreted in the context of the originating event and source schema.

For the parsed EVTX samples, [`evtx_samples_csv_field_mapping.yaml`](evtx_samples_csv_field_mapping.yaml) supplies ordered candidate columns. The EVTX preparation code records which column was selected, carries the original event fields in `raw`, and reports mapping warnings in the data-quality metadata. Event categories and actions for this pipeline are determined using [`configs/evtx_event_mapping.yaml`](../configs/evtx_event_mapping.yaml), based on the provider and event ID.

## Before changing a mapping

Check the actual source columns and the event type before adding an alias. Similar-looking fields are not always equivalent, particularly across different providers or datasets. Keep original values available so a normalized field can be traced back to its source.

The files here serve different purposes: some are mapping definitions used directly by preparation scripts, while others document shared conventions. Adding an entry to a YAML file does not automatically enable it in every ingestion path. If a change affects the generated event structure, update the corresponding preparation code and tests as well.

For the event record structure, see [`schemas/canonical_event.schema.json`](../schemas/canonical_event.schema.json). The EVTX extraction logic is in [`src/threat_hunting_data/evtx_preparation.py`](../src/threat_hunting_data/evtx_preparation.py).
