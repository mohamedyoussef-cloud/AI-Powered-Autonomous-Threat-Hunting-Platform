# Task 78: Query Validation Gate

## Overview
Validates SPL queries generated from Sigma rules (Task 56) before
execution in Splunk. Acts as a safety layer to block dangerous or
malformed queries from reaching the SIEM.

## Position in Pipeline
```
Hypothesis → LLM → Sigma → pySigma → SPL → [VALIDATION GATE] → Splunk
```

## Results
| Metric            | Value    |
|-------------------|----------|
| Total SPL queries | 394      |
| Allowed           | 394      |
| Blocked           | 0        |
| Pass rate         | 100.0% ✅ |

## Validation Checks
| Check | Description | Action if Failed |
|---|---|---|
| Empty query | Query is null or empty | BLOCK |
| Dangerous commands | Detects delete, drop, shutdown, etc. after pipe | BLOCK |
| Query too long | More than 10,000 characters | BLOCK |
| Query too short | Less than 5 characters | BLOCK |
| No search terms | No field conditions, quotes, or logic operators | BLOCK |

## Blocked Commands List
```
delete, drop, shutdown, restart, remove, truncate, purge
```

## How to Run

Step 1 - Make sure this file exists in the same folder:
```
task56_spl_results.json
```

Step 2 - Run:
```bash
python task78_validation_gate.py
```

Step 3 - Check output:
```
task78_validation_results.json
```

## How to Integrate in Backend (for Sohila)

Before sending any SPL query to Splunk, call the validation gate first:

```python
from task78_validation_gate import validate_spl_query

result = validate_spl_query(spl_query, technique_id)

if result["passed"]:
    # safe to send to Splunk
    splunk.execute(result["spl"])
else:
    # log and block
    print(f"BLOCKED: {result['reasons']}")
```

The function returns:
```json
{
  "passed": true,
  "technique_id": "T1571",
  "spl": "DestinationHostname IN (...)",
  "reasons": [],
  "action": "ALLOW"
}
```

## Important Notes for Backend Integration (Sohila)

1. The validation gate must be called BEFORE every Splunk execution —
   never send an SPL query to Splunk without passing it through
   validate_spl_query() first.

2. task78_validation_results.json already contains all 394 validated
   queries with their validation status. You can load this file directly
   instead of re-running validation for the existing test set.

3. The BLOCKLIST in task78_validation_gate.py can be extended with
   additional dangerous commands as needed — just add them to the
   BLOCKLIST list at the top of the file.

4. Queries with action=BLOCK should be logged, flagged for review,
   and never forwarded to Splunk. Consider storing them separately
   for analyst inspection.

## Output Format
Each entry in task78_validation_results.json:
```json
{
  "example_id": 0,
  "technique_id": "T1571",
  "sigma": "title: Suspicious C2 Communication...",
  "spl": "DestinationHostname IN (*.discord.com, ...)",
  "validation": {
    "passed": true,
    "technique_id": "T1571",
    "spl": "DestinationHostname IN (...)",
    "reasons": [],
    "action": "ALLOW"
  }
}
```

## Files
| File | Description |
|---|---|
| task78_validation_gate.py | Validation gate code |
| task78_validation_results.json | 394 validated SPL queries |
| README_task78.md | This file |

## Dependencies
- Python 3.9+
- No external libraries required (built-in only)

## Connection to Other Tasks
- Input comes from: Task 56 (task56_spl_results.json)
- Output goes to: Task 66 Backend — Splunk execution
- Part of: Autonomus Threat Hunting Platform