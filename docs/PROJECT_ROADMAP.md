# Project Roadmap
## AI-Powered Autonomous Threat Hunting Platform

This roadmap follows an incremental delivery model. The project focus is threat hunting, and each increment adds a specific capability to the threat hunting workflow.

## Delivery Strategy

The project will not attempt to build the full autonomous platform in one step. It will start with a core threat hunting workflow and a baseline AI engine built alongside it, then add automation and intelligence capabilities gradually.

##Search & Reference Plan
Before and during each increment, the team searches for existing GitHub repositories, datasets, and ML/LLM techniques relevant to that increment's problem, so decisions are grounded in what already exists rather than assumed. This runs from Increment 1 onward, not as a step added after implementation.
The datasets already named in the project brief are the starting point, not the full list — each still needs to be checked for size, licensing, and whether it fits the ATT&CK techniques the team ends up targeting:

MITRE ATT&CK Enterprise (STIX/TAXII)
Splunk BOTS v3 — github.com/splunk/botsv3
EVTX-ATTACK-SAMPLES — github.com/sbousseaden/EVTX-ATTACK-SAMPLES
Sigma Rules Repository — github.com/SigmaHQ/sigma
DARPA Transparent Computing datasets

Beyond these, the search covers three areas, tied to where each increment's AI work sits:
IncrementWhat to search for1 - Core MVP (AI baseline)Lightweight rule-based suggestion approaches for mapping ATT&CK techniques to hypotheses, so the baseline isn't designed blind. MITRE's own center-for-threat-informed-defense/tram project (automated ATT&CK technique mapping) is a useful reference point.2 - Hypothesis and Query GenerationExisting LLM-to-Sigma pipelines and how they keep generated rules grounded instead of hallucinated — the SigmaHQ ecosystem itself, plus published approaches like SigmaOptimizer, are worth reviewing before designing the query synthesizer.3 - Simulated Query RunnerExisting mock/simulated SIEM connector patterns for Elastic, Splunk, or Sentinel, to avoid building a connector layer from scratch.4 - ML False-Positive SuppressionPublished alert-triage research for benchmark precision/recall numbers and feature ideas — papers such as LLMCloudHunter, CORTEX, and PACT are useful starting points — plus any additional labeled alert datasets beyond BOTS v3 that could help training.5 - Case Manager and ReportingExisting hunt-report or case-management formats, so the report structure isn't invented from zero.
Anything found gets used directly: papers and prior work inform the literature review, reference repos influence the architecture decisions, and any better dataset replaces or supplements the ones listed above.

## Increment 1 - Core Threat Hunting MVP

**Goal:** Build the core business workflow for creating and tracking threat hunt campaigns.

### Included Capabilities

- Campaign dashboard
- Create/update/close campaign
- Campaign objective and risk rating
- MITRE ATT&CK tactic/technique mapping
- Hypothesis creation or selection
- Planned telemetry source selection
- Campaign lifecycle status tracking
- Analyst notes and evidence placeholders
- Basic manager review status
- Baseline AI engine setup: prompt templates, LLM connectivity, and a rule-based hypothesis suggestion

### Output

A working dashboard where a SOC analyst can create and manage a threat hunt campaign from draft to completed/closed status, with a baseline AI-assisted hypothesis suggestion already in place.

## Increment 2 - Hypothesis and Query Generation

**Goal:** Convert approved hunt hypotheses into detection logic.

### Included Capabilities
-Upgrade the baseline hypothesis suggestion into a full LLM-based Hypothesis Engine
- Query generation for one detection language first
- Analyst review/edit step
- Query validation checklist
- Storage of generated queries under the campaign

## Increment 3 - Simulated Query Runner

**Goal:** Execute or simulate query execution against public datasets or mock SIEM connectors.

### Included Capabilities

- Mock Elastic/Splunk/Sentinel connector design
- Query execution simulation
- Result collection
- Result normalization

## Increment 4 - ML False-Positive Suppression

**Goal:** Triage hunt results using a machine learning classifier.

### Included Capabilities

- Feature extraction from results
- Classifier training and testing
- Labels: confirmed threat, false positive, analyst review required
- Evaluation using precision, recall, F1-score, confusion matrix

## Increment 5 - Hunt Case Manager and Reporting

**Goal:** Convert results into structured cases and editable reports.

### Included Capabilities

- Finding-to-case workflow
- Evidence and decision tracking
- Editable Hunt Report generation
- Final manager review
