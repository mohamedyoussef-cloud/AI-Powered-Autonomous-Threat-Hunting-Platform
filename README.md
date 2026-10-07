# AI-Powered Autonomous Threat Hunting Platform

An evidence-grounded threat hunting platform that combines telemetry normalization, MITRE ATT&CK context, hypothesis generation, deterministic detection planning, Sigma rule generation and validation, Splunk execution, and finding validation.

The current repository snapshot covers the complete threat-hunting workflow through validated hunt findings. Machine-learning based finding triage is intentionally outside the scope of this revision.

## Architecture

``text
Data Sources
    |
    v
Telemetry Normalization
    |
    v
Environment and Telemetry Grounding
    |
    v
ATT&CK Applicability and Readiness
    |
    v
Threat Hunting Hypothesis Engine
    |
    v
Detection Eligibility
    |
    v
Grounded Detection Planning
    |
    v
LLM-Assisted Detection Generation
    |
    v
Sigma Structural Validation
    |
    v
Splunk Query Compilation
    |
    v
Telemetry Resolution
    |
    v
Runtime Hunt Execution
    |
    v
Candidate Validation
    |
    v
Validated Hunt Findings
``

## Design Principles

- Telemetry availability is not treated as evidence that an attack occurred.
- Unknown environment state is not converted into a negative conclusion.
- Detection generation is bounded by grounded telemetry and deterministic eligibility controls.
- LLM output is validated before it can enter execution paths.
- Sigma parsing success is treated separately from production execution readiness.
- Raw hunt candidates are not promoted to findings without validation.
- Evaluation datasets are separated using leakage-resistant train, validation, and frozen-test splits.

## Verified Repository Snapshot

| Capability | Verified result |
| --- | ---: |
| Grounded detection plans | 505 |
| Generated Sigma rules | 540 |
| Sigma structural validation | 540 / 540 |
| Sigma-to-Splunk compilation | 540 / 540 |
| Runtime execution-ready paths | 404 |
| Deferred runtime paths | 14 |
| Non-zero runtime candidates | 22 |
| Validated hunt findings | 0 |
| Fine-tuned LLM frozen-test no-blocker pass | 77.97% |
| Fine-tuned ATT&CK technique exact match | 83.57% |
| Fine-tuned ATT&CK tactic exact match | 85.31% |

A zero validated-finding count does not imply that no malicious activity exists in the underlying telemetry. It means that none of the runtime candidates satisfied the platform's current finding-validation criteria.

## LLM Detection Generation

The detection-generation model is based on Qwen3-8B and was adapted using QLoRA.

The authoritative training run used 2,322 training examples, 270 validation examples, and 286 frozen-test examples. Frozen-test evaluation was deterministic with sampling, thinking, and output repair disabled.

The LLM is not treated as an authoritative standalone production detector. Production outputs remain subject to deterministic grounding, Sigma validation, query compilation, telemetry resolution, and runtime validation.

Detailed evaluation artifacts are available under [evaluation/llm](evaluation/llm/).

## Repository Layout

``text
artifacts/
backend/
configs/
datasets/
docs/
evaluation/
frontend/
integrations/
schemas/
scripts/
src/
tests/
``

## External Assets

Large or environment-specific assets are intentionally excluded from version control, including raw BOTS v3 data, raw EVTX collections, model weights, LoRA adapter weights, Hugging Face caches, local databases, virtual environments, and secrets.

## Documentation

Start with [docs/README.md](docs/README.md) for the documentation index and [docs/VALIDATION_SNAPSHOT.md](docs/VALIDATION_SNAPSHOT.md) for the current validated results.

## Project Scope

This revision ends at validated hunt findings. Finding-level machine-learning triage and classification are intentionally not included in this repository snapshot.