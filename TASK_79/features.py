# task79_features.py
# Task 79: Runtime Feature Extraction
# =====================================
# Extracts runtime features from Splunk findings
# and passes them to the ML triage model (XGBoost).

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import uuid
import sqlite3
import numpy as np
from datetime import datetime, timezone
from collections import Counter

DB_PATH  = r"D:\AL_MASHROOOOOO3\TASKS\Backend_Task_65\threat_hunting.db"
ML_PATH  = r"D:\AL_MASHROOOOOO3\TASKS\ML\xgboost_5M_model.json"

LABEL_NAMES = {
    0: "FalsePositive",
    1: "TruePositive",
    2: "NeedsReview",
}

# ============================================
# Section 1: Load ML Model
# ============================================

try:
    from xgboost import XGBClassifier
    ml_model = XGBClassifier()
    ml_model.load_model(ML_PATH)
    ML_READY = True
    print("✅ XGBoost model loaded")
except Exception as e:
    ml_model = None
    ML_READY = False
    print(f"⚠️  XGBoost not available: {e}")

# ============================================
# Section 2: Feature Extraction
# ============================================

def extract_features(events: list, technique_id: str = "UNKNOWN") -> dict:
    """
    Extract runtime features from Splunk events.

    Features:
    1.  event_count       → total events found
    2.  unique_hosts      → how many machines affected
    3.  unique_users      → how many users involved
    4.  unique_commands   → how many unique commands
    5.  has_encoding      → encoded commands? (base64)
    6.  has_admin_user    → admin accounts involved?
    7.  has_suspicious_cmd → suspicious keywords?
    8.  event_code_count  → unique event codes
    9.  night_activity    → activity at night?
    10. avg_cmd_length    → average command length
    """

    if not events:
        return {
            "event_count":       0,
            "unique_hosts":      0,
            "unique_users":      0,
            "unique_commands":   0,
            "has_encoding":      0,
            "has_admin_user":    0,
            "has_suspicious_cmd":0,
            "event_code_count":  0,
            "night_activity":    0,
            "avg_cmd_length":    0.0,
        }

    # Basic counts
    hosts    = set()
    users    = set()
    commands = set()
    codes    = set()
    cmd_lengths    = []
    has_encoding   = 0
    has_admin      = 0
    has_suspicious = 0
    night_activity = 0

    # Suspicious keywords
    suspicious_keywords = [
        "mimikatz", "invoke-", "iex", "downloadstring",
        "bypass", "hidden", "noprofile", "encoded",
        "base64", "shellcode", "inject", "lsass",
    ]

    # Admin patterns
    admin_patterns = ["admin", "administrator", "system", "root"]

    for event in events:
        # Hosts
        host = event.get("host") or event.get("ComputerName")
        if host:
            hosts.add(host.lower())

        # Users
        user = event.get("User") or event.get("user")
        if user:
            users.add(user.lower())
            for pattern in admin_patterns:
                if pattern in user.lower():
                    has_admin = 1

        # Commands
        cmd = event.get("CommandLine") or event.get("cmd")
        if cmd:
            commands.add(cmd)
            cmd_lengths.append(len(cmd))

            # Encoding check
            if any(x in cmd.lower() for x in ["-enc", "-encodedcommand", "base64"]):
                has_encoding = 1

            # Suspicious check
            if any(kw in cmd.lower() for kw in suspicious_keywords):
                has_suspicious = 1

        # Event codes
        code = event.get("EventCode")
        if code:
            codes.add(code)

        # Night activity (00:00 - 06:00)
        time_str = event.get("_time", "")
        if time_str:
            try:
                hour = int(time_str[11:13])
                if 0 <= hour <= 6:
                    night_activity = 1
            except Exception:
                pass

    avg_cmd_length = (
        round(sum(cmd_lengths) / len(cmd_lengths), 2)
        if cmd_lengths else 0.0
    )

    return {
        "event_count":        len(events),
        "unique_hosts":       len(hosts),
        "unique_users":       len(users),
        "unique_commands":    len(commands),
        "has_encoding":       has_encoding,
        "has_admin_user":     has_admin,
        "has_suspicious_cmd": has_suspicious,
        "event_code_count":   len(codes),
        "night_activity":     night_activity,
        "avg_cmd_length":     avg_cmd_length,
    }


# ============================================
# Section 3: Run ML Triage with Real Features
# ============================================

def run_triage_with_features(
    events:       list,
    technique_id: str = "UNKNOWN",
) -> dict:
    """
    Extract features from events and run ML triage.
    """
    # Extract features
    features = extract_features(events, technique_id)

    feature_vector = np.array([[
        features["event_count"],
        features["unique_hosts"],
        features["unique_users"],
        features["unique_commands"],
        features["has_encoding"],
        features["has_admin_user"],
        features["has_suspicious_cmd"],
        features["event_code_count"],
        features["night_activity"],
        features["avg_cmd_length"],
    ]])

    if ML_READY and ml_model is not None:
        try:
            pred  = ml_model.predict(feature_vector)[0]
            proba = ml_model.predict_proba(feature_vector)[0]
            label = int(pred)
            return {
                "features":          features,
                "triage_label":      label,
                "triage_label_name": LABEL_NAMES[label],
                "triage_confidence": round(float(max(proba)), 4),
                "ml_source":         "real",
            }
        except Exception as e:
            print(f"⚠️  ML error: {e}")

    # Fallback: rule-based triage
    if features["event_count"] == 0:
        label = 0
    elif features["has_suspicious_cmd"] or features["has_encoding"]:
        label = 1
    else:
        label = 2

    return {
        "features":          features,
        "triage_label":      label,
        "triage_label_name": LABEL_NAMES[label],
        "triage_confidence": 0.5,
        "ml_source":         "rule-based fallback",
    }


# ============================================
# Section 4: Update Finding in DB
# ============================================

def update_finding_triage(finding_id: str, triage: dict) -> bool:
    """Update finding with new ML triage results"""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """UPDATE findings SET
               triage_label=?, triage_label_name=?, triage_confidence=?
               WHERE finding_id=?""",
            (
                triage["triage_label"],
                triage["triage_label_name"],
                triage["triage_confidence"],
                finding_id,
            )
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"❌ DB update error: {e}")
        return False
    finally:
        conn.close()


# ============================================
# Section 5: Process All Findings
# ============================================

def process_all_findings() -> list:
    """
    Get all findings from DB,
    extract features, run ML triage,
    update DB with new labels.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            "SELECT * FROM findings"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        print("⚠️  No findings in DB")
        return []

    results = []
    for row in rows:
        f = dict(row)

        # Parse events
        events = []
        if f.get("events"):
            try:
                events = json.loads(f["events"])
            except Exception:
                events = []

        # Run triage
        triage = run_triage_with_features(
            events       = events,
            technique_id = f.get("technique_id", "UNKNOWN"),
        )

        # Update DB
        update_finding_triage(f["finding_id"], triage)

        results.append({
            "finding_id":        f["finding_id"],
            "technique_id":      f.get("technique_id"),
            "event_count":       f.get("event_count", 0),
            "features":          triage["features"],
            "triage_label_name": triage["triage_label_name"],
            "triage_confidence": triage["triage_confidence"],
            "ml_source":         triage["ml_source"],
        })

        print(
            f"  [{f['finding_id'][:8]}] "
            f"{triage['triage_label_name']} "
            f"({triage['triage_confidence']}) "
            f"← {triage['ml_source']}"
        )

    return results


# ============================================
# Section 6: Main - Test
# ============================================

if __name__ == "__main__":
    print("=" * 55)
    print("Task 79: Runtime Feature Extraction")
    print("=" * 55)

    # Test 1: Feature extraction on mock events
    print("\n[1] Testing feature extraction...")
    mock_events = [
        {
            "_time":       "2024-01-15T02:30:00Z",
            "host":        "DESKTOP-WIN10",
            "User":        "CORP\\administrator",
            "CommandLine": "powershell.exe -enc SGVsbG8=",
            "EventCode":   "4688",
        },
        {
            "_time":       "2024-01-15T02:31:00Z",
            "host":        "DESKTOP-WIN11",
            "User":        "CORP\\admin",
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
            "EventCode":   "4688",
        },
        {
            "_time":       "2024-01-15T02:32:00Z",
            "host":        "DESKTOP-WIN10",
            "User":        "CORP\\john",
            "CommandLine": "cmd.exe /c whoami",
            "EventCode":   "4688",
        },
    ]

    features = extract_features(mock_events)
    print(f"\n  Extracted Features:")
    for k, v in features.items():
        print(f"    {k:25} : {v}")

    # Test 2: Run ML triage
    print("\n[2] Running ML triage with features...")
    triage = run_triage_with_features(mock_events, "T1059.001")
    print(f"\n  Triage Result:")
    print(f"    Label      : {triage['triage_label_name']}")
    print(f"    Confidence : {triage['triage_confidence']}")
    print(f"    ML Source  : {triage['ml_source']}")

    # Test 3: Process all findings in DB
    print("\n[3] Processing all findings in DB...")
    results = process_all_findings()

    # Save results
    output = {
        "task":      "Task 79 - Runtime Feature Extraction",
        "status":    "complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "features_defined": list(features.keys()),
        "mock_test": {
            "events":  len(mock_events),
            "triage":  triage,
        },
        "db_findings_processed": results,

        "summary": {
            "total_features":   len(features),
            "findings_updated": len(results),
            "ml_source":        "real" if ML_READY else "rule-based",
            "status":           "COMPLETE",
        }
    }

    with open("task79_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Saved: task79_results.json")
    print("\n" + "=" * 55)
    print("TASK 79 SUMMARY")
    print("=" * 55)
    print(f"Features Defined   : {len(features)} ✅")
    print(f"ML Source          : {'✅ Real' if ML_READY else '⚠️  Rule-based'}")
    print(f"Findings Updated   : {len(results)} ✅")
    print(f"Output File        : task79_results.json ✅")
    print(f"Status             : COMPLETE ✅")
    print("=" * 55)