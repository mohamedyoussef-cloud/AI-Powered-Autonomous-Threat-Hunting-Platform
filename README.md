# AI-Powered Autonomous Threat Hunting Platform

## Project Overview

This repository contains the ongoing work for the **AI-Powered Autonomous Threat Hunting Platform**, an MSc graduation project in Cybersecurity with Software Engineering / Artificial Intelligence support.

The project focuses on **proactive threat hunting**. Instead of building all advanced automation capabilities at once, the project is organized around incremental threat hunting capabilities.

## Implementation Approach

The first implementation target is the **Core Threat Hunting MVP**.

This MVP focuses on the core threat hunting workflow:

- Create and manage threat hunt campaigns
- Define campaign objective, risk level, owner, and status
- Map campaigns to MITRE ATT&CK tactics and techniques
- Create or select threat hunting hypotheses
- Select planned telemetry or dataset sources
- Track campaign lifecycle from draft to completed/closed
- Add analyst notes and evidence placeholders

This core workflow creates the foundation for later capabilities such as query generation, SIEM execution, ML triage, case management, and reporting.

## Full Platform Vision

The complete platform vision includes:

1. Threat Hunt Campaign Dashboard
2. MITRE ATT&CK-based Hypothesis Engine
3. LLM-powered Query Synthesizer
4. Automated Query Runner
5. SIEM Integrations: Elastic, Splunk, Microsoft Sentinel
6. Hunt Case Manager
7. ML False-Positive Suppression Classifier
8. Hunt Report Generator
9. Research, Experiments, and Evaluation

## Major / Minor

- **Major:** Cybersecurity
- **Minor:** Software Engineering / Artificial Intelligence

## Team Members

- Mohamed Youssef
- Mohanad Ghoraba
- Sohila Mahmoud
- Maryam Abdalbary

## Repository Structure

```text
.
├── docs/                 # BRD, SRS, architecture, roadmap, setup guides
├── research/             # literature review, methodology, research questions
├── backend/              # FastAPI backend
├── frontend/             # React dashboard
├── ai-engine/            # hypothesis engine, LLM query generator, ML classifier
├── integrations/         # Elastic, Splunk, Sentinel connectors
├── datasets/             # public dataset references and sample data notes
├── experiments/          # MSc-level experiments
├── evaluation/           # metrics, results, confusion matrices, performance reports
├── reports/              # generated hunt reports and final report drafts
├── infra/                # Docker and deployment notes
└── tests/                # unit and integration tests
```

## Technology Stack

- Backend: Python FastAPI
- Frontend: React.js + D3.js
- LLM: Ollama + Mistral-7B or StarCoder via local inference
- ML: Scikit-learn, XGBoost, RandomForest
- Async Tasks: Celery + Redis
- Database: PostgreSQL
- Search Storage: Elasticsearch
- SIEM Integrations: Elasticsearch Python Client, Splunk SDK, Microsoft Sentinel REST API
- Threat Framework: MITRE ATT&CK Enterprise
- Detection Format: Sigma Rules

## Public Datasets / Knowledge Sources

- MITRE ATT&CK Enterprise STIX/TAXII dataset
- Splunk BOTS v3 dataset
- EVTX-ATTACK-SAMPLES
- Sigma Rules Repository
- DARPA Transparent Computing datasets

## Key Documents

- BRD: `docs/BRD.md`
- Project Roadmap: `docs/PROJECT_ROADMAP.md`
- SRS: `docs/SRS.md`
- Architecture: `docs/architecture.md`
- System Design: `docs/system-design.md`

## Project Status

Planning / BRD Stage - aligned to the **Core Threat Hunting MVP**.

