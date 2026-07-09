# Business Requirements Document (BRD)
## AI-Powered Autonomous Threat Hunting Platform

**Team:** Team2  
**Team Members:** Mohamed Youssef, Mohanad Ghoraba, Sohila Mahmoud, Maryam Abdalbary   
**Degree Level:** Master of Science  
**Major:** Cybersecurity  
**Minor:** Software Engineering / Artificial Intelligence  
**Version:** 1.0  
**Status:** Ready for Academic Review  
**Implementation Approach:** Incremental threat hunting capabilities  

---

## 1. Project Overview

### 1.1 Brief Description of the Project

The **AI-Powered Autonomous Threat Hunting Platform** is a proactive cybersecurity platform designed to support Security Operations Center (SOC) teams in planning, executing, tracking, and documenting threat hunting activities.

The platform focuses on **threat hunting** as the core business domain. It is not intended to be a general SIEM replacement. Its purpose is to help SOC teams move from reactive alert-only investigation toward structured, repeatable, and measurable threat hunting campaigns.

At a high level, the platform will support the following threat hunting capabilities:

1. Threat hunt campaign planning and lifecycle tracking.
2. MITRE ATT&CK-based hypothesis creation and mapping.
3. Telemetry source planning using SIEM logs, EDR events, network flow records, or public datasets.
4. Detection query generation for selected hunt hypotheses.
5. Query execution or simulated execution against SIEM/dataset-backed telemetry.
6. Result review, finding classification, and false-positive suppression.
7. Hunt case management and editable hunt report generation.

The project will be delivered incrementally. Delivery is organized around a core threat hunting workflow and a supporting AI engine that are built side by side . The Core Threat Hunting MVP establishes the campaign workflow, hypothesis planning, MITRE ATT&CK alignment, telemetry selection, lifecycle status tracking, analyst notes, and local prototype storage. Alongside this, the MVP also introduces a baseline AI engine consisting of a rule-based hypothesis suggestion and the initial LLM connectivity scaffolding. Later increments build on this baseline, expanding it into full LLM-based query generation, ML-based triage, and AI-assisted reporting, while the core platform continues to mature in parallel.
### 1.2 Business Context

Modern SOC teams process large volumes of alerts from SIEM, EDR, firewall, endpoint, cloud, and network monitoring platforms. Many SOC workflows are reactive: analysts investigate after a detection rule fires or after a high-confidence alert is generated.

Threat hunting improves SOC maturity by allowing analysts to proactively search for attacker behavior that may not have triggered an alert. However, manual threat hunting requires knowledge of attacker tactics, MITRE ATT&CK, telemetry sources, detection engineering, query languages, and investigation workflows. This creates dependency on senior analysts and makes the process difficult to standardize.

The proposed platform provides a structured threat hunting workflow and gradually introduces automation to reduce manual effort while keeping analysts in control of review and decision-making.

### 1.3 Background

Threat hunting is a proactive cybersecurity practice in which analysts search for suspicious behavior, attacker techniques, or signs of compromise that may not appear through existing alerts.

A typical threat hunt requires the analyst to:

1. Define a hunt objective.
2. Create a hypothesis.
3. Map the hypothesis to MITRE ATT&CK tactics and techniques.
4. Identify required telemetry sources.
5. Prepare detection logic or SIEM queries.
6. Execute or simulate the search.
7. Review and triage results.
8. Document findings and decisions.
9. Produce an investigation or hunt report.

The project formalizes this workflow into a platform that supports both manual analyst-driven hunting and AI-assisted automation.

---

## 2. Business Problem / Opportunity

### 2.1 Problem Being Solved

The project addresses the following business and operational problems:

1. SOC teams often depend on reactive alerts instead of proactive hunting.
2. Threat hunting activities are commonly manual, inconsistent, and difficult to repeat.
3. Hunt campaigns may be poorly documented across spreadsheets, tickets, or informal notes.
4. Junior analysts may struggle to convert attacker behavior into structured MITRE ATT&CK-based hypotheses.
5. Different SIEM platforms require different query languages and execution workflows.
6. False positives consume analyst time and reduce SOC efficiency.
7. Threat intelligence is not always converted into actionable and repeatable hunt campaigns.
8. SOC managers may lack a clear dashboard for hunt progress, ownership, risk, and outcomes.

### 2.2 Business Opportunity Being Addressed

The platform creates an opportunity to improve SOC operations by making threat hunting more structured, measurable, repeatable, and automation-ready.

The business opportunity includes:

1. Increasing SOC maturity through proactive threat hunting.
2. Reducing manual preparation effort for hunt campaigns.
3. Improving alignment with MITRE ATT&CK.
4. Standardizing campaign ownership, status, notes, evidence, and outcomes.
5. Creating reusable hunt knowledge that can be extended into queries, results, and reports.
6. Demonstrating the value of AI-assisted cybersecurity operations in an academic MSc project.

---

## 3. Business Objectives

### 3.1 Measurable Goals

| Objective | Measurement |
|---|---|
| Establish a structured threat hunting workflow | Users can create, update, track, and close threat hunt campaigns through a dashboard |
| Improve MITRE ATT&CK alignment | Campaigns can be mapped to one or more ATT&CK tactics or techniques |
| Improve hunt planning quality | Each campaign can include an objective, hypothesis, planned telemetry sources, risk rating, and owner |
| Improve campaign visibility | Dashboard shows active campaigns, status, owner, severity/risk rating, and progress |
| Reduce manual preparation effort | Compare manual hunt planning time against platform-assisted planning time during evaluation |
| Support detection engineering | The platform can store generated or reviewed detection logic in later increments |
| Support measurable triage | ML triage can be evaluated using precision, recall, F1-score, and confusion matrix in later increments |
| Standardize reporting | Completed hunts can be converted into structured and editable hunt reports in later increments |

### 3.2 Expected Business Outcomes

1. A clear and demonstrable threat hunting workflow.
2. Better organization of hunt objectives, hypotheses, ATT&CK mappings, risk ratings, notes, evidence, and status history.
3. Reduced dependency on senior analysts for basic hunt planning.
4. A reusable foundation for query generation, SIEM/dataset execution, ML triage, and reporting.
5. Improved consistency of threat hunting documentation.
6. A research-based prototype suitable for MSc evaluation.

---

## 4. Scope

### 4.1 In Scope

The project scope is divided into **Core Threat Hunting MVP scope** and **planned expansion scope**.

#### 4.1.1 Core Threat Hunting MVP Scope

The Core Threat Hunting MVP focuses on the minimum workflow required to plan and manage threat hunting activities.

It includes:

1. A web dashboard for threat hunt campaigns.
2. Campaign creation, viewing, updating, lifecycle tracking, and closure.
3. Campaign information such as title, description, objective, severity/risk rating, owner, status, start date, and end date.
4. MITRE ATT&CK tactic and technique mapping for each campaign.
5. Hypothesis creation or selection for each campaign.
6. Planning-level telemetry source selection, such as SIEM logs, EDR events, network flow records, or public dataset references.
7. Hunt lifecycle statuses such as Draft, Ready for Review, In Progress, Findings Review, Completed, and Closed.
8. Analyst notes and evidence placeholders.
9. Basic role-based user flow for Admin, SOC Analyst, Threat Hunter, and SOC Manager.
10. Local or prototype storage of campaigns, hypotheses, ATT&CK mappings, notes, and status history.
11. Public dataset references for demonstration and future testing.

#### 4.1.2 Planned Expansion Scope

The following capabilities are part of the full project vision and will be implemented progressively after the Core Threat Hunting MVP:

1. LLM-assisted query generation for at least one detection language first, then additional languages.
2. Query review and edit screen before execution.
3. Simulated SIEM or dataset-backed query execution.
4. Native or mock integrations for Elastic SIEM, Splunk, and Microsoft Sentinel.
5. Result normalization and findings dashboard.
6. ML false-positive suppression classifier.
7. Hunt case manager with detailed evidence and investigation lifecycle.
8. Editable hunt report generator.
9. Evaluation metrics for academic validation.
10. Audit trail of important campaign and analyst actions.

### 4.2 Out of Scope

The following items are excluded from the academic prototype scope:

1. Offensive exploitation against real targets.
2. Malware execution or detonation.
3. Full enterprise SIEM replacement.
4. Full commercial EDR product development.
5. Automated containment actions such as blocking, quarantine, or host isolation.
6. Use of sensitive production data during academic testing.
7. Full commercial compliance certification.
8. Live Microsoft Sentinel deployment unless Azure resources are available.
9. Building a complete SIEM product from scratch.
10. Replacing human SOC analysts or removing analyst approval.
11. Implementing all advanced platform capabilities in the first development increment.

---

## 5. Stakeholders

This project is an MSc academic prototype. It is not being developed for a specific production SOC or a real business organization. Therefore, the primary stakeholders are the academic and project stakeholders responsible for reviewing, guiding, developing, and evaluating the work.

SOC-related roles are included as representative end-user roles to ensure that the business requirements reflect realistic threat hunting workflows.

### 5.1 Business Owners

| Stakeholder | Responsibility |
|---|---|
| Cybersecurity Department | Provides the academic and cybersecurity context for the project |
| Project Team | Owns the project scope, implementation, documentation, and delivery |
| Technical Lead | Guides the technical direction, architecture, and implementation approach |
| Team Leader | Coordinates planning, task distribution, and delivery tracking |

### 5.2 Project Sponsors

| Stakeholder | Responsibility |
|---|---|
| Academic Evaluation Committee | Reviews the project scope, documentation, implementation, and final delivery |
| Cybersecurity Department | Ensures that the project aligns with cybersecurity academic expectations |
| Project Team | Provides the effort, research, development, testing, and presentation of the solution |

### 5.3 End Users

| End User | Description |
|---|---|
| SOC Analyst | Representative user who creates and follows threat hunting campaigns |
| Threat Hunter | Representative user who defines hypotheses and investigates suspicious behavior |
| SOC Manager | Representative user who reviews campaign progress, risk ratings, and outcomes |
| Security Engineer | Representative user who supports telemetry and SIEM integration concepts in later increments |
| ML Engineer | Representative user who supports model-based triage and false-positive reduction in later increments |

### 5.4 Decision-Makers

| Decision-Maker | Decision Area |
|---|---|
| Academic Evaluation Committee | Academic approval, review, and final project evaluation |
| Cybersecurity Department | Academic and technical alignment |
| Technical Lead | Architecture, technology choices, and implementation feasibility |
| Team Leader | Delivery planning, task prioritization, and team coordination |
| Project Team | Final agreement on scope, implementation priorities, and documentation updates |

---

## 6. Business Requirements

### 6.1 High-Level Functional Requirements

#### 6.1.1 Core Threat Hunting MVP Requirements

| ID | Requirement |
|---|---|
| BR-FR-01 | The system shall allow an authorized user to create a threat hunt campaign. |
| BR-FR-02 | The system shall allow the user to define campaign information including title, description, objective, risk level, owner, and status. |
| BR-FR-03 | The system shall allow each campaign to be mapped to one or more MITRE ATT&CK tactics or techniques. |
| BR-FR-04 | The system shall allow the user to create or select a threat hunting hypothesis for the campaign. |
| BR-FR-05 | The system shall allow the user to select planned telemetry sources such as SIEM logs, EDR events, network flow records, or public dataset sources. |
| BR-FR-06 | The system shall show campaigns in a dashboard with status, risk rating, owner, and progress. |
| BR-FR-07 | The system shall support campaign lifecycle statuses such as Draft, Ready for Review, In Progress, Findings Review, Completed, and Closed. |
| BR-FR-08 | The system shall allow analysts to add notes, assumptions, evidence placeholders, and review comments to a campaign. |
| BR-FR-09 | The system shall allow SOC Manager users to review campaign status and mark campaigns as approved or requiring revision. |
| BR-FR-10 | The system shall store campaign, hypothesis, MITRE mapping, note, and status history data. |
| BR-FR-11 | The system shall allow users to search or filter campaigns by status, risk level, owner, and ATT&CK technique. |
| BR-FR-12 | The system shall provide a clear extension point for attaching generated queries, SIEM results, ML classifications, cases, and reports. |

#### 6.1.2 Planned Expansion Requirements

| ID | Requirement |
|---|---|
| BR-FR-13 | The system shall generate detection logic using an LLM-powered query synthesizer. |
| BR-FR-14 | The system shall support at least one detection language first, with Sigma, KQL, SPL, and Elasticsearch-compatible logic planned progressively. |
| BR-FR-15 | The system shall allow analysts to review and edit generated queries before execution. |
| BR-FR-16 | The system shall execute or simulate query execution against SIEM or dataset-backed telemetry. |
| BR-FR-17 | The system shall collect and normalize query results. |
| BR-FR-18 | The system shall classify findings as confirmed threat, false positive, or analyst review required. |
| BR-FR-19 | The system shall provide a Hunt Case Manager for investigation tracking. |
| BR-FR-20 | The system shall generate editable Hunt Reports. |
| BR-FR-21 | The system shall maintain an audit trail of important campaign actions. |

### 6.2 High-Level Non-Functional Requirements

| ID | Requirement |
|---|---|
| BR-NFR-01 | The system shall provide a responsive web interface suitable for dashboard-based SOC workflows. |
| BR-NFR-02 | The system shall use modular architecture so that each capability can be implemented independently and integrated gradually. |
| BR-NFR-03 | The system shall support local development and academic demonstration on limited infrastructure. |
| BR-NFR-04 | The system shall protect credentials, API keys, and configuration secrets. |
| BR-NFR-05 | The system shall support role-based access control at prototype level. |
| BR-NFR-06 | The system shall store structured campaign data in a database or prototype persistence layer. |
| BR-NFR-07 | The system shall provide clear logging and error handling for failed operations. |
| BR-NFR-08 | The system shall support measurable evaluation metrics for academic validation. |
| BR-NFR-09 | The system shall run LLM inference locally by default in AI-assisted capabilities to avoid sending sensitive telemetry to third-party providers. |
| BR-NFR-10 | The system shall use only public datasets, synthetic data, or approved demonstration data. |
| BR-NFR-11 | The system shall be designed so that long-running hunt jobs can be handled asynchronously. |
| BR-NFR-12 | The system shall be maintainable by separating frontend, backend, AI engine, integrations, datasets, evaluation, and documentation. |

---

## 7. User Roles

### 7.1 User Types

| User Type | Description |
|---|---|
| Admin | Platform administrator responsible for user access and system configuration |
| SOC Manager | Management user responsible for reviewing campaign progress and outcomes |
| Threat Hunter | Advanced security user responsible for hypothesis validation and hunt design |
| SOC Analyst | Operational user responsible for creating campaigns, reviewing results, and updating cases |
| Security Engineer | Technical user responsible for SIEM connectors and data source mapping |
| ML Engineer | Technical user responsible for training and evaluating the false-positive classifier |

### 7.2 Roles and Responsibilities

| Role | Responsibilities |
|---|---|
| Admin | Manage users, roles, integrations, and system configuration |
| SOC Manager | Monitor campaign progress, review risk, approve campaign readiness, and review final outcomes |
| Threat Hunter | Create and validate hypotheses, ATT&CK mappings, and hunt objectives |
| SOC Analyst | Create campaigns, update lifecycle status, add notes, review findings, and close campaigns |
| Security Engineer | Configure SIEM connectors, telemetry sources, and integration settings |
| ML Engineer | Train, test, and evaluate the false-positive classifier |

---

## 8. Business Process: Current and Future

### 8.1 Current As-Is Process

The current threat hunting process is mostly manual and often starts after alerts are already generated:

1. SOC receives alerts from SIEM or EDR.
2. Analyst manually reviews alerts and decides whether additional hunting is needed.
3. Analyst manually defines a hunt objective or hypothesis.
4. Analyst manually maps suspicious behavior to MITRE ATT&CK where possible.
5. Analyst manually identifies relevant data sources.
6. Analyst writes SIEM queries manually.
7. Analyst executes searches in the SIEM.
8. Analyst reviews large result sets and manually identifies false positives.
9. Analyst creates a ticket, case, or report manually.
10. SOC Manager reviews the outcome.

### 8.2 Future To-Be Process

The future process will be structured, capability-based, and gradually automated.

#### 8.2.1 Core Threat Hunting MVP Process

1. Analyst opens the Threat Hunt Campaign Dashboard.
2. Analyst creates a new hunt campaign.
3. Analyst defines the campaign objective, business risk, and target behavior.
4. Analyst maps the campaign to MITRE ATT&CK tactics or techniques.
5. Analyst creates or selects a hunt hypothesis.
6. Analyst selects planned telemetry sources or public dataset sources.
7. Analyst submits the campaign for review.
8. SOC Manager or Threat Hunter reviews the campaign.
9. Campaign status is updated throughout the lifecycle.
10. Analyst records notes, evidence placeholders, and decisions.

#### 8.2.2 Full Platform To-Be Process

1. Hypothesis Engine recommends or generates ATT&CK-aligned hunt hypotheses.
2. Query Synthesizer converts an approved hypothesis into detection logic.
3. Analyst reviews and edits the generated query.
4. Query Runner executes or simulates the hunt.
5. Results are collected and normalized.
6. ML Classifier triages findings.
7. Hunt Case Manager tracks confirmed and uncertain findings.
8. System generates an editable Hunt Report.
9. SOC Manager reviews the final campaign result.

---

## 9. Assumptions and Constraints

### 9.1 Assumptions

1. The project will be delivered incrementally through threat hunting capabilities.
2. Public datasets will be used for testing and demonstration.
3. Production customer data will not be used.
4. SIEM integrations may be implemented as mock connectors during early prototype increments.
5. Analysts will review system-generated outputs before execution.
6. ML accuracy depends on dataset quality and labeling.
7. Local deployment is acceptable for the academic prototype.
8. The platform is designed to assist analysts, not replace them.
9. The project will remain defensive, ethical, and aligned with academic cybersecurity boundaries.
10. Advanced capabilities may be simulated before full implementation.

### 9.2 Constraints

1. Limited academic implementation timeline.
2. Limited access to real SIEM platforms.
3. Limited hardware for local LLM inference.
4. Public datasets may not fully represent real enterprise networks.
5. SIEM query languages differ in syntax and capabilities.
6. LLM-generated output may contain errors and must be reviewed by humans.
7. Full Microsoft Sentinel integration may require Azure resources.
8. Some advanced capabilities may be implemented progressively after the Core Threat Hunting MVP.
9. The first demonstrable output must clearly show threat hunting value without attempting to implement the full platform at once.

---

## 10. Timeline and Milestones

The timeline below follows an incremental implementation model. Dates can be adjusted according to the academic schedule and review outcomes.

### 10.1 High-Level Implementation Phases

| Phase | Target Dates | Activities | Deliverables |
|---|---|---|---|
| Phase 1: Planning and BRD | July 1–July 7, 2026 | Finalize project scope, prepare BRD, create GitHub repository | BRD v1, GitHub repository |
| Phase 2: Core Threat Hunting Design | July 8–July 14, 2026 | Define campaign screens, entities, workflow, roles, and API structure | SRS draft, wireframes, data model |
Phase 3: Core Backend Prototype | July 15–July 28, 2026 | Build campaign APIs, status workflow, MITRE mapping structure, and storage layer, and set up the AI engine scaffolding and baseline hypothesis suggestion alongside it | Backend prototype, AI engine scaffolding
| Phase 4: Core Dashboard Prototype | July 29–August 11, 2026 | Build campaign dashboard, create/update screens, status tracking, filters, and notes | Web dashboard prototype |
Phase 5: Hypothesis and Query Generation | August 12–September 1, 2026 | Build on the Phase 3 AI scaffolding to deliver full LLM-based hypothesis support and query generation for one detection language | Query generation prototype|
|Phase 6: Query Execution or Simulation | September 2–September 15, 2026 | Add simulated SIEM execution and result collection | Query runner prototype |
| Phase 7: ML Triage | September 16–September 29, 2026 | Train and evaluate false-positive classifier | ML model and evaluation metrics |
| Phase 8: Case Management and Reporting | September 30–October 20, 2026 | Add hunt case lifecycle and editable report generation | Case and report prototype |
| Phase 9: Final Integration and Evaluation | October 21–November 10, 2026 | Integrate modules, test scenarios, compare manual vs platform-assisted workflow | Final MSc project package |

### 10.2 Key Milestones

| Milestone | Target Date |
|---|---|
| GitHub repository created | July 1, 2026 |
| BRD v1 ready for review | July 7, 2026 |
| Core threat hunting workflow and data model completed | July 14, 2026 |
| Core backend prototype completed and AI engine scaffolding completed | July 28, 2026 |
| Core dashboard prototype completed | August 11, 2026 |
| Hypothesis and query generation prototype completed | September 1, 2026 |
| Query runner prototype completed | September 15, 2026 |
| Initial ML classifier completed | September 29, 2026 |
| Case management and report generation completed | October 20, 2026 |
| Evaluation and final demo completed | November 10, 2026 |

---

## 11. Document Control

| Field | Value |
|---|---|
| Document Name | Business Requirements Document |
| Project | AI-Powered Autonomous Threat Hunting Platform |
| Version | 1.0 |
| Status | Ready for Academic Review |
| Prepared By | Team2 |
| Purpose | BRD version aligned with incremental threat hunting capability delivery |
| Implementation Approach | Core Threat Hunting MVP with a baseline AI engine, followed by progressive platform and AI capability expansion |
