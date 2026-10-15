# Canonical data and pipeline registry

Dataset source declarations, quality rules, EVTX field mapping and core pipeline contract.

## Contents
- [`llm/`](llm/) — tracked LLM experiment task/format configuration, distinct from trained checkpoint files.
- [`dataset_registry.yaml`](dataset_registry.yaml) — configuration for dataset registry
- [`pipeline_contract.yaml`](pipeline_contract.yaml) — configuration for pipeline contract
- [`quality_rules.yaml`](quality_rules.yaml) — configuration for quality rules
- **Additional tracked files:** 1 (see directory listing for complete inventory).

## Interpretation and usage

`dataset_registry.yaml` is the canonical research registry. DARPA provenance-graph data are recorded as `future_extension_only` / `excluded_from_core`, not an active training source.

[Related overview](../docs/README.md)
