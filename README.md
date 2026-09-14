# AI-Powered Autonomous Threat Hunting Platform

A governed, dataset-independent threat-hunting platform that transforms heterogeneous security telemetry into ATT&CK-aligned hunt hypotheses, grounded Detection Plans, validated Sigma rules, and SIEM-ready detection workflows.

## Current Validated Core

- 1,145 canonical records
- 2,012 telemetry evidence records: 835 operational + 1,177 regression references
- 109 MITRE ATT&CK Data Components resolved
- 697 Enterprise ATT&CK techniques evaluated
- 697/697 validated hypothesis outputs
- 505 techniques eligible for detection planning
- 505 grounded Detection Plans
- 492 plans ready for baseline Sigma generation
- 540 grounded Sigma generation units
- 540 baseline Sigma rules
- 540/540 rules successfully loaded by pySigma 1.5.0
- 0 parse errors and 0 HIGH/MEDIUM validation issues

## Architecture

Telemetry / Dataset Inputs -> Canonical Ingestion -> Environment and Telemetry Grounding -> ATT&CK Applicability / Readiness / Prioritization -> Master Hypothesis Context and Router -> Qwen Hypothesis Engine -> Detection Eligibility Gate -> Detection Plan -> Sigma Generation -> pySigma Validation -> SIEM Compilation / Controlled Execution -> Hunt Findings -> ML Triage -> Backend / Analyst UI / Automation

The LLM is a bounded component. Deterministic components retain control over applicability, telemetry readiness, eligibility, provenance, and execution gating.

## LLM Runtime

The original proposal considered a locally hosted Mistral model. During implementation, the LLM component moved to the Qwen3-8B family.

- Qwen3-8B-AWQ for local inference through vLLM
- Qwen3-8B for experimental QLoRA fine-tuning

Fine-tuning experiments are maintained separately from the deterministic production core.

## Repository Structure

- `src/` - core platform implementation
- `schemas/` - pipeline and data contracts
- `config/` and `configs/` - runtime and data-preparation configuration
- `mappings/` - field and event normalization
- `scripts/` - preparation, audit, and validation utilities
- `artifacts/` - curated validated platform outputs
- `experiments/` - experimental LLM work
- `integrations/` - SIEM connectors and query tooling
- `research/` - research and ML dataset work
- `backend/` - API/backend components
- `frontend/` - analyst interface
- `infra/` - deployment configuration
- `tests/` - automated tests
- `evaluation/` - evaluation metrics and results
- `docs/` - architecture and project documentation
- `reports/` - project and hunt reports

The internal `src/threat_hunting/phase3` package name is temporarily retained to preserve compatibility with the validated pipeline implementation. Repository organization uses functional component names rather than project-management task numbers.

## Curated Artifacts

The `artifacts/` directory contains selected reproducibility outputs for environment modeling, telemetry grounding, hypotheses, detection eligibility, Detection Plans, Sigma generation, 540 baseline Sigma rules, pySigma validation, and LLM dataset research.

Large raw or processed telemetry datasets, model weights, checkpoints, caches, secrets, and local runtime databases are intentionally excluded from Git.

## Detection Engineering Principles

- Telemetry availability does not imply attack occurrence.
- Missing evidence is not treated as evidence of absence.
- Collection gaps remain explicit.
- Unknown environment state remains unknown.
- The Hypothesis Engine does not generate SIEM queries.
- Detection eligibility is deterministic.
- Detection Plans preserve provenance.
- Sigma rules are validated before downstream SIEM compilation.
- pySigma validation alone does not imply production readiness.

## SIEM Integration

Splunk is the first implemented SIEM path. Prototype components include Sigma-to-Splunk SPL conversion and pre-execution SPL validation. Elastic and Microsoft Sentinel remain future connector targets.

## Development

Python dependencies are defined in `pyproject.toml`. Run automated tests with `pytest -q`.

## Next Development Stage

Next work focuses on robust LLM training/evaluation dataset construction, grouped held-out evaluation, production detection-generation integration, controlled Splunk execution, canonical hunt findings, ML triage, backend/frontend integration, and end-to-end automation.

## ATT&CK Knowledge Reproducibility

The ATT&CK knowledge layer under `data/processed/knowledge/` is generated and is not versioned.

Prerequisite: place the MITRE Enterprise ATT&CK 19.1 STIX bundle at:

`data/raw/mitre_attack/enterprise-attack-19.1.json`

Then generate the normalized ATT&CK knowledge artifacts with:

```powershell
python scripts/prepare_attack.py --project-root .
```

The generated artifacts are subsequently consumed by validation, Sigma preparation, and coverage-reporting workflows.
