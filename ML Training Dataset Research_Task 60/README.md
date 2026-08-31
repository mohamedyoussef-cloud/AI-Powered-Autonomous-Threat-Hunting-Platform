# Task 60: ML Training Dataset Research

## Overview
Research into suitable labeled datasets for training the ML Triage model.
The ML model classifies Splunk findings (generated from our fine-tuned
Qwen3-8B Sigma rules) into three categories:

- 1 = True Positive  (real attack confirmed)
- 0 = False Positive (benign activity mistakenly flagged)
- 2 = Needs Review   (uncertain — escalate to SOC analyst)

---

## Research Journey: Datasets Evaluated

We systematically evaluated 12+ publicly available cybersecurity datasets
before reaching our final decision. Below is a summary of each:

| Dataset | Year | What it Contains | Why Rejected |
|---|---|---|---|
| CICIDS 2017 | 2017 | Network traffic flows | Network only, no host events, outdated |
| UNSW-NB15 | 2015 | Network flows | Network only, very outdated |
| CIC-IDS2018 | 2018 | Network + Windows/Ubuntu logs | No MITRE ATT&CK, simulated |
| BETH Dataset | 2021 | Linux host events | Linux only, no Windows |
| DAPT2020 | 2020 | APT network + auditd logs | Host data not labeled, small (460MB) |
| SCVIC-APT2021 | 2021 | APT flows | 18.4% synthetic data, very small (61K) |
| TON_IoT | 2020 | IoT + OS logs | 100% accuracy = too easy, IoT-focused |
| CICIoMT2024 | 2024 | Medical IoT traffic | IoT medical devices, not relevant |
| EMBER2024 | 2024 | PE file features | Static malware analysis, not runtime events |
| Purple Team | Unknown | Red+Blue team events | Poor documentation, not original data |
| LANL Unified | 2017 | Windows host + network | Not labeled (no TP/FP labels) |
| OTRF Security-Datasets | Ongoing | ATT&CK-mapped Windows/Linux | No pre-built labels, requires manual work |
| GUIDE (Microsoft) | 2024 | Real SOC incidents | ✅ Selected — see below |

---

## Why We Changed from 3 Datasets to 2

### Original Selection (before analysis):
We initially selected three datasets:
- OTRF Security-Datasets
- CICIDS 2017
- BETH Dataset

### Why We Changed:

**CICIDS 2017 was dropped because:**
- Network traffic only (no Windows/Linux host events)
- Our Sigma rules are 89% Windows/Linux host-based after filtering
- GUIDE covers network events better and with real-world labels

**BETH Dataset was dropped because:**
- Linux only (no Windows coverage)
- Our Sigma rules are 89% Windows-focused
- GUIDE covers Linux events too (via OSFamily column)

**GUIDE was added because:**
After downloading and analyzing the actual data (50,000 rows sample),
we discovered GUIDE provides exactly what we need:
- Real-world incidents from 6,100+ organizations ✅
- Pre-built labels: TruePositive / FalsePositive / BenignPositive ✅
- MITRE ATT&CK mapping (441 techniques) ✅
- Incident-level data matching our Splunk findings format ✅
- 1 million+ labeled incidents (largest available) ✅
- Published 2024 (most recent available) ✅

---

## Final Selected Datasets

### Dataset 1: GUIDE (Microsoft Security Incident Prediction)
**Link:** https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction

**What it contains (from actual data analysis):**

EntityType distribution (from 50,000 sample):

| EntityType | Count | % | Sigma Coverage |
|---|---|---|---|
| Ip | 11,364 | 22.7% | network_connection ✅ |
| User | 10,289 | 20.6% | authentication rules ✅ |
| MailMessage | 6,083 | 12.2% | email-based attacks ✅ |
| Url | 3,702 | 7.4% | webserver + dns_query ✅ |
| Machine | 3,614 | 7.2% | host events ✅ |
| File | 3,564 | 7.1% | file_event ✅ |
| CloudLogonRequest | 3,310 | 6.6% | Azure rules ✅ |
| Process | 1,774 | 3.5% | process_creation ⚠️ |
| RegistryKey/Value | 102 | 0.2% | registry_set ⚠️ |

Label distribution:

| Label | Count | % | Maps To |
|---|---|---|---|
| BenignPositive | 21,527 | 43.1% | label 2 (Needs Review) |
| TruePositive | 17,418 | 34.8% | label 1 (Attack) |
| FalsePositive | 10,779 | 21.6% | label 0 (Benign) |

**Why chosen:**
- ✅ Only public dataset with real-world SOC labels at incident level
- ✅ Labels match exactly what our ML model needs (TP/FP/BP)
- ✅ Incident-level data matches Splunk findings format
- ✅ MITRE ATT&CK techniques mapped per alert
- ✅ Covers network, file, cloud, and identity events
- ✅ Most recent (2024) and largest (1M+ incidents)

**Limitations:**
- ⚠️ OSFamily is encoded as numbers (anonymized) — cannot confirm exact Windows/Linux split
- ⚠️ Process events only 3.5% — lower than our 51% process_creation Sigma rules
- ⚠️ Registry events only 0.2% — lower than our 5% registry Sigma rules
- ⚠️ Large file size (2.43 GB) — requires sufficient storage

---

### Dataset 2: OTRF Security-Datasets
**Link:** https://github.com/OTRF/Security-Datasets

**What it contains:**
- Simulated attack scenarios mapped to MITRE ATT&CK
- Windows Event Logs: process creation, registry, file events
- Linux audit logs (auditd)
- JSON format per technique

**Why chosen:**
- ✅ Directly covers process_creation (51% of our Sigma rules)
- ✅ Covers registry_set (5% of our Sigma rules)
- ✅ Mapped to ATT&CK techniques = easy labeling
- ✅ Known attack scenarios = label 1 (True Positive)
- ✅ Complementary to GUIDE — covers what GUIDE lacks

**Limitations:**
- ⚠️ No pre-built labels at finding level — requires manual labeling
- ⚠️ Simulated attacks (not real-world)
- ⚠️ Smaller than GUIDE

**Labeling strategy for OTRF:**
```
Attack scenario events  → label 1 (True Positive)
Normal/benign events    → label 0 (False Positive)
```

---

## Why We Decided NOT to Filter Training Data

### Original plan:
We initially planned to filter train.jsonl to keep only
Windows + Linux rules, removing Azure, Cisco, macOS, AWS rules.

This would reduce training data from 3,770 → 3,321 examples.

### Why we reversed this decision:

**1. GUIDE covers Azure rules well:**
```
Azure rules in training data: 122 examples (3%)
GUIDE coverage of Azure:
  - CloudLogonRequest: 6.6%
  - User accounts:    20.6%
  - AzureResource:     0.1%
```
Keeping Azure rules means we can better utilize GUIDE's
cloud-related incidents for ML training.

**2. More data = better ML model:**
```
With filtering:    3,321 training examples
Without filtering: 3,770 training examples (+13.5% more data)
```

**3. Coverage comparison:**
```
With filtering:    GUIDE covers ~35-40% of Sigma rules
Without filtering: GUIDE covers ~40-45% of Sigma rules
```

**4. Conclusion:**
Filtering reduces both training data volume and GUIDE coverage
with no meaningful benefit. The original train.jsonl is used as-is.

Note: train_filtered.jsonl was created as a backup option
in case retraining is needed in the future.

---

## Coverage Summary

How well do our selected datasets cover the Sigma rule categories
generated by our fine-tuned model?

| Sigma Category | % of Rules | GUIDE Coverage | OTRF Coverage | Combined |
|---|---|---|---|---|
| process_creation | 51% | ⚠️ 3.5% | ✅ High | ✅ Good |
| file_event | 6% | ✅ 7.1% | ✅ High | ✅ Excellent |
| ps_script | 5% | ⚠️ Low | ✅ High | ✅ Good |
| registry_set | 5% | ❌ 0.2% | ✅ High | ✅ Good |
| image_load | 4% | 🟡 7.2% Machine | ✅ Medium | ✅ Good |
| network_connection | 3% | ✅ 22.7% Ip | ❌ Low | ✅ Good |
| webserver | 3% | ✅ 7.4% Url | ❌ Low | ✅ Good |
| dns_query | 1% | ✅ 7.4% Url | ❌ Low | ✅ Good |

**Estimated total coverage: ~85-90% of Sigma rule categories**

---

## Files Generated During Research

| File | Description |
|---|---|
| check_guide.py | Script to analyze GUIDE dataset distribution |
| check_guide_2.py | Script to analyze OSFamily encoding |
| check_guide_3.py | Script to analyze Category + EntityType |
| check_guide_4.py | Script to compute full percentages |
| data_training.py | Script to analyze training data distribution |
| filtering.py | Script to filter training data (backup only) |
| train_filtered.jsonl | Filtered training data (backup, not used) |
| sigma_count.py | Script to count Sigma rule categories |

---

## Next Steps (Task 61-62)

Task 61: Select train/val/test splits from GUIDE + OTRF
Task 62: Prepare features and labels for ML training

---

## Dependencies
- Python 3.9+
- pandas: pip install pandas
- pyyaml: pip install pyyaml

## Part of
Autonomus Threat Hunting Platform
Task 60: ML Training Dataset Research
