# Task 79: Runtime Feature Extraction

## Overview
Extracts runtime features from Splunk findings and passes them to the ML triage model (XGBoost). When Splunk is installed, real events will replace mock events automatically.

## Pipeline
Splunk Events → Feature Extraction → XGBoost ML → TP/FP/NeedsReview

## Features Extracted (10 features)
| Feature | Description |
|---------|-------------|
| event_count | Total events found |
| unique_hosts | How many machines affected |
| unique_users | How many users involved |
| unique_commands | How many unique commands |
| has_encoding | Encoded commands detected (base64) |
| has_admin_user | Admin accounts involved |
| has_suspicious_cmd | Suspicious keywords (mimikatz, lsass...) |
| event_code_count | Unique event codes |
| night_activity | Activity between 00:00 - 06:00 |
| avg_cmd_length | Average command length |

## API Endpoint
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/findings/{id}/features | Get extracted features for a finding |

## Files
| File | Description |
|------|-------------|
| features.py | Feature extraction + ML triage |
| task79_results.json | Test results |

## How to Run
    python features.py

## Status
| Component | Status |
|-----------|--------|
| Feature Extraction | ✅ Ready |
| ML Model | ✅ Real XGBoost |
| Splunk Events | ⏳ Awaiting Splunk |
| API Integration | ✅ Ready |

## Results
| Metric | Value |
|--------|-------|
| Features Defined | 10 ✅ |
| ML Source | ✅ Real XGBoost |
| Findings Updated | 3 ✅ |
| Status | COMPLETE ✅ |