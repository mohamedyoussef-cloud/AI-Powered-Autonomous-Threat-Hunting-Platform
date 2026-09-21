# Task 70: Analyst Feedback Workflow

## Overview
Captures analyst feedback on findings and uses it to improve the ML model over time. Every analyst verdict is saved as a potential training example for future ML retraining.

## How it Works
Analyst gives verdict → System compares with ML prediction → Saves to feedback table → Exports wrong predictions as training data

## Verdict to Label Mapping
| Verdict | Label | Meaning |
|---------|-------|---------|
| confirmed | 1 | TruePositive |
| rejected | 0 | FalsePositive |
| escalated | 2 | NeedsReview |

## Database Table: feedback
| Column | Type | Description |
|--------|------|-------------|
| feedback_id | TEXT | Unique UUID |
| finding_id | TEXT | Linked finding |
| hunt_id | TEXT | Linked hunt |
| technique_id | TEXT | ATT&CK technique |
| analyst_verdict | TEXT | confirmed / rejected / escalated |
| analyst_notes | TEXT | Analyst comments |
| analyst_name | TEXT | Who gave the verdict |
| original_label | INTEGER | What ML predicted |
| corrected_label | INTEGER | What analyst said |
| was_ml_wrong | INTEGER | 1=Wrong / 0=Correct |
| created_at | TEXT | Timestamp |

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | /api/findings/{id}/feedback | Submit analyst feedback |
| GET | /api/feedback/stats | Get ML accuracy from feedback |

## Files
| File | Description |
|------|-------------|
| feedback.py | Feedback workflow + ML correction tracking |
| task70_results.json | Test results |

## How to Run
    python feedback.py

## Results
| Metric | Value |
|--------|-------|
| Feedback Table | ✅ |
| Verdict Tracking | ✅ |
| ML Correction Detection | ✅ |
| Training Data Export | ✅ |
| API Endpoints | ✅ |
| Status | COMPLETE ✅ |