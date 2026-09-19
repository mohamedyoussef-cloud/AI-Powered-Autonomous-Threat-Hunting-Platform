```
# Task 57 & 58: Hunt Findings Collection and Normalization

## Overview
| Task | Name | Status |
|------|------|--------|
| 57 | Hunt Findings Data Model | ✅ Complete |
| 58 | Findings Collection and Normalization | ⏳ Ready (awaiting Splunk) |

---

## Task 57: Hunt Findings Data Model

### What is it?
Defines the canonical format (HuntFinding) for every
result returned by Splunk hunt execution.
This is the direct input for the ML Triage model.

### HuntFinding Fields (14 fields)
| Field | Type | Description |
|-------|------|-------------|
| finding_id | str | Unique UUID per finding |
| technique_id | str | ATT&CK technique (e.g. T1059) |
| technique_name | str | ATT&CK technique name |
| tactic | str | ATT&CK tactic |
| hypothesis | str | Original hypothesis text |
| sigma_rule_id | str | UUID of Sigma rule used |
| spl_query | str | SPL query executed |
| event_count | int | Number of Splunk events |
| events | list | Raw normalized Splunk events |
| hunt_timestamp | str | When the hunt was executed |
| earliest_event | str | Earliest event time |
| latest_event | str | Latest event time |
| triage_label | int | 0=FP / 1=TP / 2=NeedsReview |
| triage_confidence | float | ML confidence score (0.0-1.0) |

### Triage Labels
| Label | Value | Action |
|-------|-------|--------|
| False Positive | 0 | auto-close |
| True Positive | 1 | act now |
| Needs Review | 2 | escalate to SOC analyst |

### Results
| Metric | Value |
|--------|-------|
| Examples validated | 2/2 ✅ |
| Fields defined | 14 ✅ |
| Status | COMPLETE ✅ |

### How to use
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
    splunk_events  = [...],
)

# Validate
result = validate_finding(finding)
print(result["valid"])  # True
```

---

## Task 58: Findings Collection and Normalization

### What is it?
Executes all 394 validated SPL queries against Splunk,
collects the results, and normalizes them into
canonical HuntFinding format for the ML Triage model.

### Pipeline
```
task56_spl_results.json (394 SPL queries)
        ↓
Splunk Execution (REST API)
        ↓
Raw Events
        ↓
Normalization → HuntFinding format
        ↓
task58_findings.json
        ↓
ML Triage Model (XGBoost)
```

### How to run
```
1. pip install splunk-sdk
2. Edit password in task58_splunk_execution.py
3. python task58_splunk_execution.py
```

### Expected Output
```json
{
  "summary": {
    "total_queries":  394,
    "success":        "???",
    "total_events":   "???",
    "total_findings": 394
  },
  "findings": [...]
}
```

### Status
| Component | Status |
|-----------|--------|
| Code | ✅ Ready |
| Splunk | ⏳ Awaiting installation |
| Data (BOTS v3) | ⏳ Awaiting download |
| Execution | ⏳ Pending |

---

## Files
| File | Task | Description |
|------|------|-------------|
| `findings_model.py` | 57 | Canonical HuntFinding data model |
| `task57_results.json` | 57 | Validation results + examples |
| `task58_splunk_execution.py` | 58 | Splunk execution + normalization |
| `task58_findings.json` | 58 | Output findings (pending) |

---

## Dependencies
| Dependency | Status |
|------------|--------|
| task56_spl_results.json | ✅ Ready |
| task78 validated queries | ✅ Ready |
| Splunk Enterprise | ⏳ Pending |
| BOTS v3 Dataset | ⏳ Pending |
| splunk-sdk (pip) | ⏳ Pending |

---

## Next Step
```
1. Install Splunk Enterprise → localhost:8000
2. Load BOTS v3 dataset
3. pip install splunk-sdk
4. Run task58_splunk_execution.py
5. Output → task58_findings.json → ML Triage
```
```

