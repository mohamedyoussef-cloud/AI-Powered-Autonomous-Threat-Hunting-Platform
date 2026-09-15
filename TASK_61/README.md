# Task 61: ML Train / Validation / Test Dataset Selection

## Overview
Selection of final training, validation, and test splits for the
ML Triage model. The model classifies Splunk findings into:

- 0 = False Positive  (benign activity)
- 1 = True Positive   (real attack)
- 2 = Needs Review    (escalate to SOC analyst)

---

## Selected Dataset: GUIDE (Microsoft Security Incident Prediction)

**Link:** https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction

**Why GUIDE only (not ORTF):**

Due to time constraints, we proceeded with GUIDE as the sole dataset
for this task. GUIDE alone provides sufficient data for initial ML
model training with 647,344 labeled incidents across all three splits.

ORTF (Security-Datasets) was evaluated and found to be technically
suitable (Windows + Linux attack scenarios mapped to MITRE ATT&CK),
however its format requires significant preprocessing effort:
- Each scenario is stored as a separate ZIP file containing JSON logs
- No unified schema across scenarios
- No pre-built benign/malicious labels
- Would require manual labeling and feature extraction

ORTF integration is planned as a future improvement once the baseline
ML model is trained and evaluated. Adding ORTF data in a later
iteration is expected to improve coverage of process_creation and
registry_set events (currently underrepresented in GUIDE).

---

## Data Processing Steps

### Step 1: Load and Sample GUIDE_Train.csv
The full training file contains 9,516,837 rows (8.72 GB in memory).
To make training feasible on available hardware, we sampled 500,000
rows while preserving label distribution.

```
Full GUIDE_Train.csv : 9,516,837 rows
After removing nulls : 9,465,497 rows
Sample taken         :   500,000 rows → GUIDE_sample.csv
```

### Step 2: Load and Sample GUIDE_Test.csv
The full test file contains 4,147,992 rows (4.07 GB in memory).
We sampled 150,000 rows to create a manageable test set.

```
Full GUIDE_Test.csv  : 4,147,992 rows
After removing nulls : 4,147,992 rows
Sample taken         :   150,000 rows → GUIDE_test_sample.csv
```

### Step 3: Split Training Sample into Train + Validation
The 500,000-row sample was split 80/20 using stratified splitting
to preserve label balance across both splits.

```python
train, val = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df["IncidentGrade"]
)
```

---

## Final Splits

| Split | File | Rows | % |
|---|---|---|---|
| Train | GUIDE_train_final.csv | 397,875 | 61.4% |
| Validation | GUIDE_val_final.csv | 99,469 | 15.4% |
| Test | GUIDE_test_sample.csv | 150,000 | 23.2% |
| **Total** | | **647,344** | **100%** |

---

## Label Distribution Across Splits

| Label | Train | Val | Test |
|---|---|---|---|
| BenignPositive (2) | 172,356 (43.3%) | 43,089 (43.3%) | 63,472 (42.3%) |
| TruePositive (1) | 139,993 (35.2%) | 34,998 (35.2%) | 54,007 (36.0%) |
| FalsePositive (0) | 85,526 (21.5%) | 21,382 (21.5%) | 32,521 (21.7%) |

Labels are well-balanced across all three splits — no significant
class imbalance requiring additional resampling techniques.

---

## Label Mapping for ML Model

| GUIDE Label | ML Label | Meaning |
|---|---|---|
| TruePositive | 1 | Real attack — act immediately |
| FalsePositive | 0 | Benign — safe to close |
| BenignPositive | 2 | Uncertain — escalate to SOC analyst |

---

## Key Columns Available for Feature Engineering (Task 62)

| Column | Type | Description |
|---|---|---|
| Category | Categorical | Attack category (InitialAccess, Malware...) |
| EntityType | Categorical | Type of entity involved (Process, File, Ip...) |
| OSFamily | Encoded int | Operating system family |
| MitreTechniques | Text | ATT&CK technique IDs |
| DetectorId | Encoded int | Alert detector identifier |
| AlertTitle | Text | Title of the alert |
| IncidentGrade | Target label | TruePositive / FalsePositive / BenignPositive |

---

## Leakage Prevention

- Train/Val split is done at row level with stratification
- Test set comes from GUIDE_Test.csv (a completely separate file
  that was never used during training or validation)
- random_state=42 ensures reproducibility

---

## Future Work: ORTF Integration

ORTF Security-Datasets (https://github.com/OTRF/Security-Datasets)
was downloaded and evaluated. It contains Windows and Linux attack
scenarios mapped to MITRE ATT&CK techniques, which would complement
GUIDE's lower coverage of process_creation (3.5%) and registry
events (0.2%).

Integration plan (to be done after baseline ML model is trained):

1. Extract Windows event logs from atomic/windows/ ZIP files
2. Label attack events as TruePositive (label 1)
3. Generate benign baseline events as FalsePositive (label 0)
4. Align schema with GUIDE feature format
5. Merge with existing train/val splits
6. Retrain ML model and compare performance

Expected improvement: better detection of process-based and
registry-based attacks, which represent ~56% of our Sigma rules.

---

## Files Generated

| File | Description | Rows |
|---|---|---|
| GUIDE_sample.csv | 500K sample from GUIDE_Train | 497,344 |
| GUIDE_train_final.csv | Final training set (80%) | 397,875 |
| GUIDE_val_final.csv | Final validation set (20%) | 99,469 |
| GUIDE_test_clean.csv | Full cleaned test set | 4,147,992 |
| GUIDE_test_sample.csv | Sampled test set (150K) | 150,000 |

---

## Scripts Used

| Script | Purpose |
|---|---|
| check_guide.py | Analyze label and entity distribution |
| check_guide_2.py | Analyze OSFamily encoding |
| check_guide_3.py | Analyze Category vs EntityType |
| check_guide_4.py | Compute full percentage distributions |
| check_guide_5.py | Load and inspect full GUIDE_Train.csv |
| Guide_test_cleaning.py | Load and clean GUIDE_Test.csv |
| Guide_test_sample.py | Sample 150K rows from test set |
| Guide_val.py | Split sample into train/val 80/20 |

---

## Dependencies

```
pip install pandas scikit-learn
```

## Part of
Autonomus Threat Hunting Platform
Task 61: ML Train / Validation / Test Dataset Selection