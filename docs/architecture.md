# System Architecture

## Architecture Direction

The full platform architecture is modular. Implementation starts with the Core Threat Hunting MVP and a baseline AI engine, then adds full LLM-based query generation, SIEM execution, ML triage, case management, and reporting.
## Core Threat Hunting MVP Architecture Scope

```text
React Dashboard
      |
      v
FastAPI Backend
      |
      +--> Campaign Service
      +--> MITRE Mapping Service
      +--> Hypothesis Planning Service
      +--> Notes / Status History Service
      +--> AI Engine (baseline)
      |
      v
Database / Prototype Storage
```

## Full Platform Target Architecture

```text
React Dashboard
      |
      v
FastAPI Backend
      |
      +--> Campaign Service
      +--> Hunt Case Service
      +--> Report Service
      +--> Integration Service
      |
      v
AI Engine
      |
      +--> MITRE ATT&CK Hypothesis Engine
      +--> LLM Query Synthesizer
      +--> ML False-Positive Classifier
      |
      v
SIEM Connectors / Mock Connectors
      |
      +--> Elastic SIEM
      +--> Splunk
      +--> Microsoft Sentinel
```

## Main Components

1. Frontend Dashboard
2. FastAPI Backend
3. Campaign and Hypothesis Planning Services
4. AI Engine
5. SIEM Integration Layer
6. PostgreSQL Storage
7. Elasticsearch Search Storage
8. Celery + Redis Async Processing
9. Report Generation Module
