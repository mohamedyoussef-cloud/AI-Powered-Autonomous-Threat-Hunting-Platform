# AI-Powered Autonomous Threat Hunting Platform

An AI-powered **proactive threat hunting platform** designed to help Security Operations Center (SOC) teams continuously plan, execute, validate, and track threat hunting activities across enterprise telemetry.

The platform operates as a controlled, read-only threat hunting orchestration and decision-support layer. It transforms organizational context, MITRE ATT&CK knowledge, telemetry availability, and historical security observations into structured hunt hypotheses, detection logic, executable SIEM searches, and validated hunt findings.

Rather than relying exclusively on reactive alert-driven workflows, the platform enables proactive investigation of adversary behavior that may evade existing detection rules, remain below alert thresholds, abuse legitimate tools, or develop gradually across multiple stages of an intrusion.

The architecture combines deterministic security controls, LLM-assisted reasoning and detection generation, governed SIEM execution, and downstream analytical validation while preserving analyst oversight for security-sensitive decisions.

---

## Platform Purpose

Modern SOC environments generate large volumes of alerts across SIEM, EDR, identity, cloud, network, and application-security platforms. Alert-driven investigation remains essential, but it is inherently reactive: investigation typically begins after a rule, correlation, or detection mechanism has already raised a signal.

The **AI-Powered Autonomous Threat Hunting Platform** extends SOC operations with a proactive hunting capability.

Its objective is to systematically search for attacker behavior before it becomes a confirmed incident by combining:

- MITRE ATT&CK-guided hunt reasoning
- environment and telemetry awareness
- autonomous hypothesis generation
- deterministic detection eligibility
- structured detection planning
- Sigma detection generation
- validation and safety controls
- SIEM query compilation and execution
- hunt finding validation
- downstream triage and analyst review

The platform is designed to operate as a controlled **Tier 3 Analyst capability**, augmenting experienced security teams rather than replacing the SIEM, EDR, SOAR, or human analyst.

---

## Proactive Threat Hunting Model

The platform is built around the distinction between **reactive detection** and **proactive hunting**.

Reactive workflows remain important for responding to known detections and high-confidence alerts. Threat hunting addresses a different operational need: searching for adversary behavior that may not yet have produced a reliable alert.

The platform therefore focuses on converting security context and telemetry into structured hunts that can be reasoned about, validated, executed, and reviewed in a repeatable way.

```text
Enterprise Context & Telemetry
        ↓
Environment / Telemetry Grounding
        ↓
MITRE ATT&CK Applicability & Readiness
        ↓
Proactive Hunt Hypothesis Generation
        ↓
Detection Eligibility
        ↓
Detection Planning
        ↓
Sigma Detection Generation
        ↓
Validation & Safety Controls
        ↓
SIEM Query Compilation / Execution
        ↓
Hunt Findings
        ↓
Validation / Triage / Analyst Review
```

---

## System Architecture

The current implementation separates deterministic controls, LLM reasoning, detection engineering, and runtime execution into explicit stages.

```text
Canonical Ingestion
        ↓
Environment Profiling
        ↓
Telemetry Evidence Resolution
        ↓
ATT&CK Applicability
        ↓
Telemetry Readiness & Collection Gap Analysis
        ↓
Master Hypothesis Context
        ↓
Hypothesis Router
        ↓
Qwen3-8B Hypothesis Engine
        ↓
Detection Eligibility Gate
        ↓
Detection Plan
        ↓
Sigma Generation
        ↓
pySigma Validation
        ↓
Splunk Compilation
        ↓
Telemetry Evidence Gate
        ↓
Runtime Hunt Execution
        ↓
Candidate Finding Validation
        ↓
Validated Hunt Findings
```

---

## Core Capabilities

### Environment and Telemetry Grounding

The platform builds a grounded representation of the current security environment before any hunt logic is generated.

It explicitly separates:

```text
Environment Presence
        ≠
Telemetry Availability
        ≠
ATT&CK Applicability
        ≠
Observed Activity
        ≠
Malicious Activity
```

This prevents unsupported assumptions such as treating an available log source as proof that a specific attack behavior occurred.

### MITRE ATT&CK Reasoning

MITRE ATT&CK is used as the behavioral framework for:

- technique and tactic mapping
- environment applicability
- telemetry requirements
- hunt hypothesis construction
- detection planning
- Sigma metadata
- evaluation and traceability

### Autonomous Hunt Hypothesis Generation

The hypothesis engine receives a grounded, route-specific context and generates structured hunt hypotheses using Qwen3-8B.

The LLM does not decide whether a technique is applicable, whether telemetry is sufficient, or whether a hunt result is a confirmed finding.

### Detection Eligibility

A deterministic eligibility gate decides whether a validated hypothesis may proceed into detection planning.

This separates hunt reasoning from production detection generation and prevents unsupported or blocked techniques from being promoted downstream.

### Detection Planning

Eligible hypotheses are converted into structured detection plans containing authoritative, grounded generation inputs.

Deterministic fields remain authoritative. LLM output is used only where semantic enrichment is appropriate.

### Sigma Detection Generation

The platform converts grounded detection plans into Sigma detections.

Sigma acts as the common detection representation before SIEM-specific compilation.

### Validation and SIEM Execution

Generated Sigma rules are structurally validated with pySigma, compiled into Splunk SPL, filtered through a telemetry evidence gate, and only then considered for runtime execution.

### Hunt Finding Validation

Runtime matches are treated as **finding candidates**, not automatically confirmed threats.

Candidates must pass further analysis before they are promoted into validated hunt findings.

---

## AI and Deterministic Control Boundaries

The platform does not treat the LLM as the system orchestrator.

The LLM is used for bounded reasoning and generation tasks, while high-impact security decisions remain deterministic.

The LLM does **not** control:

- environment state
- ATT&CK applicability
- telemetry readiness
- detection eligibility
- authoritative detection-plan fields
- pySigma validation
- SIEM execution controls
- final finding promotion

This design keeps probabilistic model behavior inside controlled boundaries and preserves auditability across the threat hunting workflow.

---

## Current Validated Implementation

The repository currently contains the validated implementation through runtime hunt execution and finding validation.

| Component | Validated Result |
|---|---:|
| ATT&CK techniques processed | 697 |
| Validated hunt hypotheses | 697 / 697 |
| Runtime Hunt routes | 522 |
| Collection Gap routes | 49 |
| Environment Resolution routes | 30 |
| PRE routes | 96 |
| Detection-eligible techniques | 505 |
| Detection plans | 505 |
| Grounded detection paths | 540 |
| Sigma rules generated | 540 |
| pySigma structural validation | 540 / 540 |
| Splunk compilation | 540 / 540 |
| Literal runtime candidates | 418 |
| Runtime-ready hunts | 404 |
| Deferred runtime hunts | 14 |
| Runtime executions | 404 |
| Zero / inconclusive executions | 381 |
| Non-zero candidate executions | 22 |
| Execution errors | 1 |
| Validated hunt findings | 0 |

The 381 zero-match executions remain operationally inconclusive where telemetry visibility is incomplete.

The 22 non-zero candidates were reviewed through keyword-contribution analysis and were rejected because their matches were dominated by broad or shared keywords rather than sufficiently specific malicious evidence.

The absence of validated findings therefore means that no candidate met the platform's promotion criteria in this execution snapshot. It does **not** mean that malicious activity was absent from the monitored environment.

---

## ATT&CK and Telemetry Snapshot

The current grounded environment contains:

- **697** ATT&CK techniques evaluated
- **571** currently applicable techniques
- **30** environment-unknown techniques
- **96** PRE techniques
- **522** runtime-hunt candidates
- **49** collection-gap techniques
- **109** ATT&CK Data Components evaluated

The platform keeps collection gaps, unknown environment state, and attack occurrence as separate concepts throughout the pipeline.

---

## Detection Planning Snapshot

The current detection planning stage contains:

- **505** final detection plans
- **492** plans ready for baseline Sigma generation
- **13** plans requiring additional path resolution
- **540** grounded detection-generation paths

The downstream generation pipeline uses the deterministic detection-plan fields as authoritative inputs.

---

## LLM Fine-Tuning and Evaluation

The project uses **Qwen3-8B** with parameter-efficient **QLoRA** fine-tuning for Sigma-generation research.

The supervised split used for the final training run contains:

| Split | Records |
|---|---:|
| Train | 2,322 |
| Validation | 270 |
| Frozen Test | 286 |

The frozen test set was isolated from training and used to compare the untuned base model with the fine-tuned model.

### Frozen Test Results

| Metric | Base Model | Fine-Tuned Model |
|---|---:|---:|
| Strict / YAML validity | 79.02% | 87.76% |
| Parse success | 61.89% | 80.42% |
| No-blocker pass rate | 0.00% | 77.97% |
| ATT&CK technique accuracy | 9.09% | 83.57% |
| ATT&CK tactic accuracy | 0.70% | 85.31% |
| Log source accuracy | 73.43% | 78.67% |
| Detection level accuracy | 12.94% | 81.47% |

The fine-tuned model substantially improves structured Sigma generation and ATT&CK metadata accuracy, but it is not treated as a standalone production authority.

Production reliability comes from the complete grounded pipeline: deterministic planning, generation controls, structural validation, SIEM compilation, telemetry evidence gating, runtime execution controls, and finding validation.

---

## Sigma Generation and Validation

The baseline Sigma generation pipeline produces rules only from grounded detection-plan paths.

Current generation results:

```text
Generation units:     540
Generated Sigma:      540
Generation errors:      0
Model calls:            0
Audit failures:         0
```

The current baseline generator is deterministic.

All generated Sigma rules pass structural validation:

```text
pySigma validation
------------------
Passed: 540
Failed:   0
```

A pySigma PASS confirms that the rule is structurally valid for the validation pipeline.

It does **not** by itself prove that the rule is operationally observable, production-ready, or capable of producing reliable findings in a specific environment.

---

## Splunk Compilation and Runtime Execution

Validated Sigma detections are compiled into Splunk SPL using the Splunk pySigma backend.

```text
Sigma rules:          540
Compiled SPL:         540
Compilation failures:  0
```

A telemetry evidence gate is applied before runtime execution.

```text
Literal candidates: 418
Runtime ready:      404
Deferred:            14
```

Runtime execution results:

```text
Executed:              404
Zero / inconclusive:   381
Non-zero candidates:    22
Execution errors:        1
Validated findings:      0
```

Runtime execution and finding validation are intentionally separate stages.

A query match is a candidate that requires interpretation and validation, not an automatically confirmed threat.

---

## Repository Structure

```text
.
├── artifacts/
│   ├── detection-plans/
│   ├── hunt-findings/
│   ├── sigma/
│   └── splunk/
│
├── configs/
│   └── llm/
│
├── datasets/
│   └── llm/
│
├── docs/
│
├── evaluation/
│   └── llm/
│
├── integrations/
│   └── splunk/
│
├── research/
│
├── scripts/
│   └── llm/
│
└── src/
    └── threat_hunting/
```

### Key Artifact Locations

```text
artifacts/detection-plans/
    Detection planning outputs and grounded generation contexts

artifacts/sigma/rules/
    Canonical Sigma rule population

artifacts/sigma/generation/
    Sigma generation summaries and audits

artifacts/sigma/validation/
    pySigma validation outputs

artifacts/splunk/compilation/
    Compiled SPL and compilation metadata

artifacts/splunk/telemetry-resolution/
    Runtime telemetry evidence resolution

artifacts/splunk/runtime/
    Runtime execution queues and results

artifacts/splunk/finding-validation/
    Candidate finding analysis

artifacts/hunt-findings/
    Final dispositions and validated findings

datasets/llm/
    Supervised and fine-tuning datasets

evaluation/llm/
    Base-model, fine-tuned-model, validation, and training evidence
```

---

## Architecture Portability

The platform is designed so that dataset- or source-specific assumptions remain outside the core reasoning pipeline.

Canonical interfaces separate ingestion from downstream hunting logic so the same architecture can be extended to future SIEM, EDR, cloud, endpoint, or laboratory telemetry sources without rewriting the core threat hunting stages.

This is an architectural property of the implementation, not the primary product definition.

---

## Validation Boundaries

The project intentionally avoids overstating security conclusions.

### Structural Sigma Validation

```text
pySigma PASS
```

means the Sigma rule passed structural validation.

It does not mean:

```text
production detection confirmed
```

### Runtime Execution

```text
0 matches
```

does not automatically mean:

```text
attack absent
```

especially where telemetry visibility is incomplete.

### LLM Evaluation

```text
77.97% no-blocker pass rate
```

is the standalone fine-tuned model result on the frozen test set.

It is not reported as 100% production reliability.

### Hunt Findings

```text
validated_hunt_findings = 0
```

means no runtime candidate passed the current finding-promotion criteria.

It does not mean that the environment was free from malicious activity.

---

## Technology Stack

The current implementation uses:

- Python
- MITRE ATT&CK
- Sigma
- pySigma
- Splunk SPL
- Qwen3-8B
- LoRA / QLoRA
- Hugging Face Transformers
- PEFT
- PyTorch

---

## Current Scope

The validated repository currently covers:

```text
Ingestion
→ Environment & Telemetry Grounding
→ ATT&CK Applicability & Readiness
→ Hypothesis Generation
→ Detection Eligibility
→ Detection Planning
→ LLM Fine-Tuning
→ Sigma Generation
→ pySigma Validation
→ Splunk Compilation
→ Runtime Hunt Execution
→ Finding Validation
```

The supervised ML triage / false-positive classification stage has not yet been trained and is intentionally outside the current validated snapshot.

---

## Project Status

The current release represents a validated **pre-ML autonomous threat hunting pipeline** with:

- proactive ATT&CK-guided hunt reasoning
- grounded environment and telemetry awareness
- deterministic eligibility and detection planning
- Qwen3-8B fine-tuning and frozen-test evaluation
- deterministic Sigma generation
- pySigma validation
- Splunk compilation
- runtime hunt execution
- candidate finding validation

The next major stage is supervised finding-level ML triage using trustworthy labels and leakage-resistant dataset construction.
