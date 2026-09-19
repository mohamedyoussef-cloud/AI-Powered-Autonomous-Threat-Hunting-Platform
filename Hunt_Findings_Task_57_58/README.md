# Task 57: Hunt Findings Data Model

## What is this?
Defines the canonical format for every finding
returned by Splunk hunt execution.
This finding is the direct input for the ML Triage model.

## Files
| File | Description |
|------|-------------|
| `findings_model.py` | Canonical HuntFinding data model |
| `task57_results.json` | Validation results + examples |

## HuntFinding Fields (14 fields)
| Field | Type | Description |
|-------|------|-------------|
| finding_id | str | Unique UUID per finding |
| technique_id | str | ATT&CK technique (e.g. T1059) |
| technique_name | str | ATT&CK technique name |
| tactic | str | ATT&CK tactic |
| hypothesis | str | Original hypothesis text |
| sigma_rule_id | str | UUID of the Sigma rule used |
| spl_query | str | SPL query executed in Splunk |
| event_count | int | Number of Splunk events returned |
| events | list | Raw Splunk events |
| hunt_timestamp | str | When the hunt was executed |
| earliest_event | str | Earliest event time |
| latest_event | str | Latest event time |
| triage_label | int | 0=FP / 1=TP / 2=NeedsReview |
| triage_confidence | float | ML confidence score (0.0-1.0) |

## Triage Labels


0 = False Positive  → auto-close
1 = True Positive   → act now
2 = Needs Review    → escalate to SOC analyst


## Results

Examples validated : 2/2 ✅
Fields defined     : 14  ✅
Status             : COMPLETE ✅


## How to use
```python
from findings_model import HuntFindingBuilder, validate_finding

# Build finding from Splunk results
finding = HuntFindingBuilder.from_splunk_results(
    technique_id   = "T1059.001",
    technique_name = "PowerShell",
    tactic         = "Execution",
    hypothesis     = "your hypothesis here",
    sigma_rule_id  = "uuid-here",
    spl_query      = "index=* EventCode=4688...",
    splunk_events  = [...],  # from Splunk SDK
)

# Validate
result = validate_finding(finding)
print(result["valid"])  # True