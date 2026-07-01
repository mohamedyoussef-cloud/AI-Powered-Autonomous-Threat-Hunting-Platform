# Software Requirements Specification
## AI-Powered Autonomous Threat Hunting Platform

**Current Technical Focus:** Core Threat Hunting MVP  
**Version:** 1.0  
**Status:** Initial Technical Scope

## 1. Purpose

This SRS defines the first technical implementation scope derived from the BRD. The first release focuses on the Core Threat Hunting MVP before adding query generation, query execution, ML triage, case management, and reporting.

## 2. MVP Functional Requirements

| ID | Requirement |
|---|---|
| SRS-FR-01 | The system shall allow authorized users to create threat hunt campaigns. |
| SRS-FR-02 | The system shall allow users to update campaign title, description, objective, risk level, owner, status, start date, and end date. |
| SRS-FR-03 | The system shall allow campaigns to be mapped to MITRE ATT&CK tactics and techniques. |
| SRS-FR-04 | The system shall allow users to add or select a hypothesis for each campaign. |
| SRS-FR-05 | The system shall allow users to select planned telemetry sources or public dataset references. |
| SRS-FR-06 | The system shall show campaigns in a dashboard with filtering by status, risk level, owner, and ATT&CK technique. |
| SRS-FR-07 | The system shall support status transitions: Draft, Ready for Review, In Progress, Findings Review, Completed, and Closed. |
| SRS-FR-08 | The system shall allow analysts to add notes, assumptions, and evidence placeholders. |
| SRS-FR-09 | The system shall allow manager review status to be recorded. |
| SRS-FR-10 | The system shall store campaign data, hypothesis data, MITRE mappings, notes, and status history. |

## 3. Initial API Direction

| API | Method | Purpose |
|---|---|---|
| `/campaigns` | GET | List campaigns with filters |
| `/campaigns` | POST | Create a campaign |
| `/campaigns/{id}` | GET | View campaign details |
| `/campaigns/{id}` | PUT | Update campaign information |
| `/campaigns/{id}/status` | PATCH | Update campaign lifecycle status |
| `/campaigns/{id}/mitre-mappings` | POST | Add ATT&CK tactic or technique mapping |
| `/campaigns/{id}/hypotheses` | POST | Add or select campaign hypothesis |
| `/campaigns/{id}/notes` | POST | Add analyst note or evidence placeholder |

## 4. Initial Data Entities

- User
- ThreatHuntCampaign
- CampaignStatusHistory
- MitreMapping
- HuntHypothesis
- TelemetrySource
- AnalystNote
- ManagerReview

## 5. Non-Functional Requirements

- The MVP shall run locally for academic demonstration.
- The system shall avoid using sensitive production data.
- Generated or AI-assisted outputs in later increments shall require analyst review.
- The codebase shall remain modular so query generation, SIEM execution, ML triage, cases, and reports can be added progressively.
