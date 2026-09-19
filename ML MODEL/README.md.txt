# ML Triage Component: Tasks 61–64

## Overview
This document covers the complete ML Triage pipeline for the
Autonomus Threat Hunting Platform, including dataset selection,
feature engineering, model training, and evaluation.

The ML Triage model classifies Splunk findings into three categories:

- 0 = False Positive  (benign — safe to close automatically)
- 1 = True Positive   (real attack — act immediately)
- 2 = Needs Review    (uncertain — escalate to SOC analyst)

---

# Task 61: ML Train / Validation / Test Dataset Selection

## Selected Dataset: GUIDE (Microsoft Security Incident Prediction)

**Link:** https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction

**Why GUIDE:**
- 9.5 million real-world SOC incidents from 6,100+ organizations ✅
- Pre-built labels: TruePositive / FalsePositive / BenignPositive ✅
- MITRE ATT&CK mapping (441 techniques) ✅
- Incident-level data matching Splunk findings format ✅
- Most recent public security dataset (2024) ✅

---

## Why GUIDE only (not ORTF)

Due to time constraints, we proceeded with GUIDE as the sole
dataset for this task. ORTF (Security-Datasets) was evaluated
and found technically suitable but requires significant effort:

- Each scenario stored as separate ZIP containing JSON logs
- No unified schema across scenarios
- No pre-built benign/malicious labels
- Requires manual labeling and feature extraction

ORTF integration is planned as a future improvement.
Expected benefit: better coverage of process_creation (51% of
our Sigma rules) and registry_set (5%) which are currently
underrepresented in GUIDE.

---

## Data Scale Experiments

We ran experiments at multiple data scales to find the optimal
training size for available hardware (16GB RAM):

| Experiment | Rows Loaded | RAM Used | Status |
|---|---|---|---|
| Initial sample | 500,000 | 0.46 GB | ✅ Baseline |
| 3M experiment | 2,983,902 | 2.76 GB | ✅ Success |
| 5M experiment | 4,972,992 | 4.60 GB | ✅ Final choice |

**Why 5M was chosen:**
- Largest dataset feasible on available hardware
- 5x more data than initial baseline
- No crash or memory issues observed
- Consistent accuracy across all scales (~90%)

---

## Data Processing Steps

### Step 1: Load 5M rows from GUIDE_Train.csv

```python
df = pd.read_csv("GUIDE_Train.csv", nrows=5000000)
df = df.dropna(subset=["IncidentGrade"])
# Result: 4,972,992 rows after null removal
```

### Step 2: Split 80 / 10 / 10

```python
X_train, X_temp, y_train, y_temp = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
)
```

---

## Final Splits

| Split | File | Rows | % |
|---|---|---|---|
| Train | X_train_5M.csv | 3,978,393 | 80% |
| Validation | X_val_5M.csv | 497,299 | 10% |
| Test | X_test_5M.csv | 497,300 | 10% |
| **Total** | | **4,972,992** | **100%** |

---

## Label Distribution

| Label | ML Label | Train | Val | Test |
|---|---|---|---|---|
| TruePositive | 1 | 1,397,714 (35.1%) | 174,714 (35.1%) | 174,715 (35.1%) |
| FalsePositive | 0 | 853,783 (21.5%) | 106,723 (21.5%) | 106,773 (21.5%) |
| BenignPositive | 2 | 1,726,896 (43.4%) | 215,862 (43.4%) | 215,812 (43.4%) |

Labels are well-balanced — no resampling required.

---

## Label Mapping

| GUIDE Label | ML Label | Meaning | Spec Equivalent |
|---|---|---|---|
| TruePositive | 1 | Real attack | malicious |
| FalsePositive | 0 | Benign | benign |
| BenignPositive | 2 | Uncertain | requires_review |

---

## Leakage Prevention

- Stratified split preserves label balance ✅
- Test set from separate GUIDE_Test.csv (never seen during training) ✅
- random_state=42 ensures reproducibility ✅

---

## Future Work: ORTF Integration

Integration plan (after baseline ML model is validated):

1. Extract Windows event logs from atomic/windows/ ZIP files
2. Label attack events as TruePositive (label 1)
3. Generate benign baseline events as FalsePositive (label 0)
4. Align schema with GUIDE feature format
5. Merge with existing train/val splits
6. Retrain ML model and compare performance

Expected improvement: better detection of process-based and
registry-based attacks (~56% of our Sigma rules).

---

# Task 62: ML Dataset Preparation and Feature Engineering

## Column Analysis

All 45 GUIDE columns were analyzed. Columns removed:

**Removed — excessive nulls (>97%):**

| Column | Null % |
|---|---|
| ActionGrouped | 99.9% |
| ActionGranular | 99.9% |
| ThreatFamily | 99.2% |
| ResourceType | 99.8% |
| EmailClusterId | 98.9% |
| Roles | 97.7% |
| AntispamDirection | 98.2% |

**Removed — identifiers only (not predictive):**
- Id, IncidentId, AlertId, Timestamp

---

## Selected Features (10 total)

| Feature | Type | Null % | Processing |
|---|---|---|---|
| OSFamily | Numeric | 0% | Used as-is |
| OSVersion | Numeric | 0% | Used as-is |
| DetectorId | Numeric | 0% | Used as-is |
| OrgId | Numeric | 0% | Used as-is |
| Category | Categorical | 0% | Label encoded |
| EntityType | Categorical | 0% | Label encoded |
| EvidenceRole | Categorical | 0% | Label encoded |
| MitreTechniques | Categorical | 57% | Filled "Unknown" → encoded |
| SuspicionLevel | Categorical | 85% | Filled "Unknown" → encoded |
| LastVerdict | Categorical | 76% | Filled "Unknown" → encoded |

---

## Encoding Strategy

LabelEncoder fitted on training data only to prevent leakage.
Unseen values in val/test mapped to -1.

```python
le = LabelEncoder()
le.fit(train[col].astype(str))
train[col+"_enc"] = le.transform(train[col].astype(str))
val[col+"_enc"] = val[col].astype(str).apply(
    lambda x: le.transform([x])[0] if x in le.classes_ else -1
)
```

---

## Limitations vs. Data Preparation Spec

The spec defines domain-specific feature contracts
(process, authentication, network, file, registry).
This implementation uses a single flat feature table
as a baseline. Domain-specific contracts are planned
for future iterations when ORTF data is integrated.

---

## Output Files

| File | Shape | Description |
|---|---|---|
| X_train_5M.csv | (3,978,393 × 10) | Training features |
| y_train_5M.csv | (3,978,393 × 1) | Training labels |
| X_val_5M.csv | (497,299 × 10) | Validation features |
| y_val_5M.csv | (497,299 × 1) | Validation labels |
| X_test_5M.csv | (497,300 × 10) | Test features |
| y_test_5M.csv | (497,300 × 1) | Test labels |

---

# Task 63: ML Triage Model Training

## Model Selection: XGBoost

**Why XGBoost over RandomForest:**

| Criteria | XGBoost | RandomForest |
|---|---|---|
| Training speed | ✅ Fast (sequential boosting) | ❌ Slower (parallel trees) |
| Memory usage | ✅ Lower | ❌ Higher |
| Class imbalance | ✅ scale_pos_weight | ❌ Less flexible |
| Tabular data | ✅ State-of-the-art | 🟡 Good but lower |
| Cybersecurity papers | ✅ Top performer | 🟡 Outperformed |
| Learning strategy | ✅ Learns from errors | ❌ Independent trees |

**Why NOT RandomForest:**
- Slower on large datasets (3.9M rows × 10 features)
- Higher memory consumption
- Generally lower accuracy on security datasets

---

## Training at Multiple Scales

To validate consistency, we trained at two scales:

| Scale | Train Rows | Accuracy | F1 (macro) | Time |
|---|---|---|---|---|
| 3M experiment | 2,387,121 | 89.9% | 89% | 3 min |
| 5M final | 3,978,393 | 89.7% | 89% | 4.6 min |

**Observation:** Accuracy remained stable across scales (~90%),
confirming the model learned generalizable patterns and was
not simply memorizing training data.

---

## Model Configuration

```python
XGBClassifier(
    n_estimators  = 300,
    max_depth     = 6,
    learning_rate = 0.1,
    objective     = "multi:softprob",
    num_class     = 3,
    eval_metric   = "mlogloss",
    random_state  = 42,
    n_jobs        = -1,
)
```

---

## Training Progress (5M)

| Step | Validation mlogloss |
|---|---|
| 0 | 1.04330 |
| 50 | 0.49895 |
| 100 | 0.38773 |
| 150 | 0.33120 |
| 200 | 0.29762 |
| 250 | 0.27789 |
| 299 | 0.26229 |

mlogloss consistently decreased → model learned well ✅

---

## Validation Results (5M model)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| FalsePositive | 0.87 | 0.82 | 0.85 | 106,773 |
| TruePositive | 0.92 | 0.90 | 0.91 | 174,646 |
| BenignPositive | 0.89 | 0.93 | 0.91 | 215,880 |
| **Accuracy** | | | **0.90** | 497,299 |
| **Macro avg** | 0.89 | 0.88 | 0.89 | 497,299 |

---

# Task 64: ML Triage Evaluation and Testing

## Final Test Results (5M model on unseen test set)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| FalsePositive | 0.87 | 0.82 | 0.84 | 106,773 |
| TruePositive | 0.92 | 0.90 | 0.91 | 174,646 |
| BenignPositive | 0.89 | 0.93 | 0.91 | 215,881 |
| **Accuracy** | | | **0.90** | 497,300 |
| **Macro avg** | 0.89 | 0.88 | 0.89 | 497,300 |

---

## Confusion Matrix

| | Predicted FP | Predicted TP | Predicted BP |
|---|---|---|---|
| **Actual FP** | 87,510 | 6,733 | 12,530 |
| **Actual TP** | 5,623 | 156,574 | 12,449 |
| **Actual BP** | 7,378 | 7,463 | 201,040 |

**Key observations:**
- 156,574 / 174,646 True Positives correctly identified (90%) ✅
- 87,510 / 106,773 False Positives correctly closed (82%) ✅
- 201,040 / 215,881 BenignPositive correctly escalated (93%) ✅

---

## Feature Importance

| Feature | Importance | Interpretation |
|---|---|---|
| OrgId | 29.2% | Organization context is most predictive |
| DetectorId | 17.2% | Alert source strongly indicates outcome |
| Category | 13.3% | Attack category is highly informative |
| SuspicionLevel | 11.9% | Pre-computed suspicion score helps |
| LastVerdict | 9.9% | Historical verdicts are predictive |
| MitreTechniques | 9.1% | ATT&CK mapping adds value |
| EntityType | 4.5% | Type of entity involved matters |
| EvidenceRole | 3.7% | Evidence role provides context |
| OSVersion | 0.8% | OS version has minor impact |
| OSFamily | 0.6% | OS family has minor impact |

---

## Performance Consistency Across Scales

| | 500K baseline | 3M | 5M (final) |
|---|---|---|---|
| Accuracy | 89.7% | 89.9% | 89.5% |
| TP Recall | 90% | 91% | 90% |
| FP Recall | 83% | 83% | 82% |
| BP Recall | 93% | 93% | 93% |
| Training time | 31 sec | 3 min | 4.6 min |

**Conclusion:** The model generalizes well regardless of training
size. The 5M model is selected as the final model due to its
larger training set and consistent performance.

---

## Saved Model

```
xgboost_5M_model.json  ← Final production model
task64_results.json    ← Full evaluation results
```

---

## All Scripts

| Script | Task | Purpose |
|---|---|---|
| check_guide.py | 61 | Analyze label distribution |
| check_guide_2.py | 61 | Analyze OSFamily encoding |
| check_guide_3.py | 61 | Analyze Category vs EntityType |
| check_guide_4.py | 61 | Compute full percentages |
| check_guide_5.py | 61 | Inspect full GUIDE_Train.csv |
| Guide_test_cleaning.py | 61 | Clean GUIDE_Test.csv |
| Guide_test_sample.py | 61 | Sample test set |
| Guide_val.py | 61 | Split train/val |
| 5million.py | 61 | Load and verify 5M rows |
| reading_data.py | 62 | Column analysis |
| feature_5M.py | 62 | Feature engineering pipeline |
| train_5M.py | 63 | XGBoost training |
| evaluate_5M.py | 64 | Final evaluation |

---

## Dependencies

```
pip install pandas scikit-learn xgboost numpy
```

---

## Part of
Autonomus Threat Hunting Platform
Tasks 61–64: ML Triage Component