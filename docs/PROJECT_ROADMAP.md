# Project Roadmap
## AI-Powered Autonomous Threat Hunting Platform

This roadmap follows an incremental delivery model. The project focus is threat hunting, and each increment adds a specific capability to the threat hunting workflow.

## Delivery Strategy

The project will not attempt to build the full autonomous platform in one step. It will start with a core threat hunting workflow and a baseline AI engine built alongside it, then add automation and intelligence capabilities gradually.

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
