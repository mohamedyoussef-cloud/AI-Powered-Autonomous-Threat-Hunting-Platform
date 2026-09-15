# Task 62: ML Dataset Preparation and Feature Engineering

## Overview
Preparation of normalized, ML-ready features from the GUIDE dataset
for training the ML Triage model. The model classifies Splunk findings
into three categories:

- 0 = False Positive  (benign — safe to close automatically)
- 1 = True Positive   (real attack — act immediately)
- 2 = Needs Review    (uncertain — escalate to SOC analyst)

---

## Input Files

| File | Rows | Description |
|---|---|---|
| GUIDE_train_final.csv | 397,875 | Training set from Task 61 |
| GUIDE_val_final.csv | 99,469 | Validation set from Task 61 |
| GUIDE_test_sample.csv | 150,000 | Test set from Task 61 |

---

## Step 1: Column Analysis

All 45 columns were analyzed for data type and null percentage:

Columns removed due to excessive nulls (>99%):

| Column | Null % | Reason |
|---|---|---|
| ActionGrouped | 99.9% | Not useful |
| ActionGranular | 99.9% | Not useful |
| EmailClusterId | 98.9% | Not useful |
| ThreatFamily | 99.2% | Not useful |
| ResourceType | 99.8% | Not useful |
| Roles | 97.7% | Not useful |
| AntispamDirection | 98.2% | Not useful |

Columns removed as identifiers (not predictive):

| Column | Reason |
|---|---|
| Id | Unique identifier only |
| IncidentId | Unique identifier only |
| AlertId | Unique identifier only |
| Timestamp | Requires complex time-series processing |

---

## Step 2: Feature Selection

10 features were selected based on predictive value and data quality:

| Feature | Type | Null % | Processing |
|---|---|---|---|
| OSFamily | Numeric | 0% | Used as-is |
| OSVersion | Numeric | 0% | Used as-is |
| DetectorId | Numeric | 0% | Used as-is |
| OrgId | Numeric | 0% | Used as-is |
| Category | Categorical | 0% | Label encoded |
| EntityType | Categorical | 0% | Label encoded |
| EvidenceRole | Categorical | 0% | Label encoded |
| MitreTechniques | Categorical | 57% | Filled with "Unknown" then encoded |
| SuspicionLevel | Categorical | 85% | Filled with "Unknown" then encoded |
| LastVerdict | Categorical | 76% | Filled with "Unknown" then encoded |

---

## Step 3: Label Encoding

Target variable mapping:

| GUIDE Label | ML Label | Meaning |
|---|---|---|
| FalsePositive | 0 | Benign — auto-close |
| TruePositive | 1 | Real attack — act now |
| BenignPositive | 2 | Uncertain — escalate |

---

## Step 4: Categorical Feature Encoding

LabelEncoder was fitted on training data only to prevent data leakage.
Unseen values in validation and test sets were mapped to -1.

```python
le = LabelEncoder()
le.fit(train[col].astype(str))          # fit on train only
train[col+"_enc"] = le.transform(...)   # transform train
val[col+"_enc"]   = val[col].apply(     # handle unseen values
    lambda x: le.transform([x])[0]
    if x in le.classes_ else -1
)
```

---

## Output Files

| File | Shape | Description |
|---|---|---|
| X_train.csv | (397,875 × 10) | Training features |
| y_train.csv | (397,875 × 1) | Training labels |
| X_val.csv | (99,469 × 10) | Validation features |
| y_val.csv | (99,469 × 1) | Validation labels |
| X_test.csv | (150,000 × 10) | Test features |
| y_test.csv | (150,000 × 1) | Test labels |

---

## Label Distribution

| Label | Train | Val | Test |
|---|---|---|---|
| 2 - BenignPositive | 172,356 (43.3%) | 43,089 (43.3%) | 63,472 (42.3%) |
| 1 - TruePositive | 139,993 (35.2%) | 34,998 (35.2%) | 54,007 (36.0%) |
| 0 - FalsePositive | 85,526 (21.5%) | 21,382 (21.5%) | 32,521 (21.7%) |

Labels are well-balanced — no resampling required.

---

## Preparation for Task 63: ML Model Training

### Selected Model: XGBoost

**Why XGBoost over RandomForest:**

| Criteria | XGBoost | RandomForest |
|---|---|---|
| Training speed | ✅ Fast (sequential boosting) | ❌ Slower (parallel trees) |
| Memory usage | ✅ Lower | ❌ Higher |
| Class imbalance handling | ✅ scale_pos_weight parameter | ❌ Less flexible |
| Tabular data performance | ✅ State-of-the-art | 🟡 Good but lower |
| Cybersecurity ML papers | ✅ Top performer | 🟡 Common but outperformed |
| Learning strategy | ✅ Learns from previous errors | ❌ Independent trees |
| Interpretability | 🟡 Medium (SHAP values) | 🟡 Medium (feature importance) |

**Why NOT RandomForest:**
- Slower training on large datasets (397K rows × 10 features)
- Higher memory consumption
- Generally lower accuracy on security datasets
  (confirmed by systematic review in Task 60 research)

### Planned XGBoost Configuration

```python
XGBClassifier(
    n_estimators    = 300,
    max_depth       = 6,
    learning_rate   = 0.1,
    objective       = "multi:softprob",
    num_class       = 3,
    eval_metric     = "mlogloss",
    use_label_encoder = False,
    random_state    = 42,
)
```

### Evaluation Metrics (Task 64)
- Accuracy
- Macro F1-score (recommended for imbalanced multi-class)
- Per-class Precision and Recall
- Confusion Matrix

---

## Leakage Prevention Summary

- LabelEncoder fitted on training data only ✅
- Null filling strategy defined on training data only ✅
- Test set from separate GUIDE_Test.csv file ✅
- random_state=42 for reproducibility ✅

---

## Scripts

| Script | Purpose |
|---|---|
| reading_data.py | Column analysis and null inspection |
| Feature_Engineering.py | Full feature engineering pipeline |

---

## Dependencies

```
pip install pandas scikit-learn numpy
```

## Part of
Autonomus Threat Hunting Platform
Task 62: ML Dataset Preparation and Feature Engineering