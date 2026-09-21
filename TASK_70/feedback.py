# task70_feedback.py
# Task 70: Analyst Feedback Workflow
# ====================================
# Captures analyst feedback on findings
# and uses it to improve the ML model.

import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import uuid
import sqlite3
import numpy as np
from datetime import datetime, timezone
from pathlib import Path

DB_PATH      = r"D:\AL_MASHROOOOOO3\TASKS\Backend_Task_65\threat_hunting.db"
ML_PATH      = r"D:\AL_MASHROOOOOO3\TASKS\ML\xgboost_5M_model.json"
FEEDBACK_LOG = "task70_feedback_log.json"

# ============================================
# Section 1: Feedback Table
# ============================================

FEEDBACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id       TEXT PRIMARY KEY,
    finding_id        TEXT NOT NULL,
    hunt_id           TEXT NOT NULL,
    technique_id      TEXT,

    -- Analyst Input
    analyst_verdict   TEXT NOT NULL,
    analyst_notes     TEXT,
    analyst_name      TEXT,

    -- ML Correction
    original_label      INTEGER,
    original_label_name TEXT,
    corrected_label      INTEGER,
    corrected_label_name TEXT,
    was_ml_wrong         INTEGER,

    -- Timestamps
    created_at TEXT NOT NULL,

    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
"""

def init_feedback_table():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(FEEDBACK_SCHEMA)
    conn.commit()
    conn.close()
    print("✅ Feedback table ready")


# ============================================
# Section 2: Verdict to Label Mapping
# ============================================

VERDICT_TO_LABEL = {
    "confirmed":  1,   # TruePositive
    "rejected":   0,   # FalsePositive
    "escalated":  2,   # NeedsReview
}

LABEL_NAMES = {
    0: "FalsePositive",
    1: "TruePositive",
    2: "NeedsReview",
}


# ============================================
# Section 3: Submit Feedback
# ============================================

def submit_feedback(
    finding_id:     str,
    analyst_verdict: str,
    analyst_notes:  str  = None,
    analyst_name:   str  = None,
) -> dict:
    """
    Submit analyst feedback for a finding.
    Saves feedback and checks if ML was wrong.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # Get finding
        finding = conn.execute(
            "SELECT * FROM findings WHERE finding_id=?",
            (finding_id,)
        ).fetchone()

        if not finding:
            return {"error": f"Finding {finding_id} not found"}

        finding = dict(finding)

        # Get corrected label from verdict
        corrected_label = VERDICT_TO_LABEL.get(analyst_verdict, 2)
        original_label  = finding.get("triage_label", 2)
        was_ml_wrong    = 1 if corrected_label != original_label else 0

        feedback_id = str(uuid.uuid4())
        now         = datetime.now(timezone.utc).isoformat()

        # Save feedback
        conn.execute(
            """INSERT INTO feedback
               (feedback_id, finding_id, hunt_id, technique_id,
                analyst_verdict, analyst_notes, analyst_name,
                original_label, original_label_name,
                corrected_label, corrected_label_name,
                was_ml_wrong, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                feedback_id,
                finding_id,
                finding["hunt_id"],
                finding.get("technique_id", "UNKNOWN"),
                analyst_verdict,
                analyst_notes,
                analyst_name,
                original_label,
                LABEL_NAMES.get(original_label, "Unknown"),
                corrected_label,
                LABEL_NAMES.get(corrected_label, "Unknown"),
                was_ml_wrong,
                now,
            )
        )

        # Update finding verdict
        conn.execute(
            "UPDATE findings SET analyst_verdict=? WHERE finding_id=?",
            (analyst_verdict, finding_id)
        )
        conn.commit()

        result = {
            "feedback_id":         feedback_id,
            "finding_id":          finding_id,
            "analyst_verdict":     analyst_verdict,
            "original_label":      LABEL_NAMES.get(original_label, "Unknown"),
            "corrected_label":     LABEL_NAMES.get(corrected_label, "Unknown"),
            "was_ml_wrong":        bool(was_ml_wrong),
            "created_at":          now,
        }

        if was_ml_wrong:
            print(f"  ⚠️  ML was WRONG!")
            print(f"     ML said    : {LABEL_NAMES.get(original_label)}")
            print(f"     Analyst said: {LABEL_NAMES.get(corrected_label)}")
        else:
            print(f"  ✅ ML was CORRECT!")
            print(f"     Both said: {LABEL_NAMES.get(original_label)}")

        return result

    finally:
        conn.close()


# ============================================
# Section 4: Get Feedback Stats
# ============================================

def get_feedback_stats() -> dict:
    """Get overall ML performance from analyst feedback"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            "SELECT * FROM feedback"
        ).fetchall()

        if not rows:
            return {"error": "No feedback yet"}

        total        = len(rows)
        ml_wrong     = sum(1 for r in rows if r["was_ml_wrong"] == 1)
        ml_correct   = total - ml_wrong
        accuracy     = round(ml_correct / total * 100, 2) if total > 0 else 0

        # Count by verdict
        verdict_counts = {
            "confirmed": 0,
            "rejected":  0,
            "escalated": 0,
        }
        for row in rows:
            v = row["analyst_verdict"]
            if v in verdict_counts:
                verdict_counts[v] += 1

        # Count ML errors by label
        ml_errors = {}
        for row in rows:
            if row["was_ml_wrong"] == 1:
                original = row["original_label_name"]
                if original not in ml_errors:
                    ml_errors[original] = 0
                ml_errors[original] += 1

        return {
            "total_feedback":  total,
            "ml_correct":      ml_correct,
            "ml_wrong":        ml_wrong,
            "ml_accuracy":     f"{accuracy}%",
            "verdict_counts":  verdict_counts,
            "ml_errors_by_label": ml_errors,
        }

    finally:
        conn.close()


# ============================================
# Section 5: Export Feedback as Training Data
# ============================================

def export_training_data() -> list:
    """
    Export feedback as new training examples
    for ML model retraining.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # Get wrong predictions only
        rows = conn.execute(
            """SELECT f.*, fi.event_count
               FROM feedback f
               JOIN findings fi ON f.finding_id = fi.finding_id
               WHERE f.was_ml_wrong = 1"""
        ).fetchall()

        training_data = []
        for row in rows:
            training_data.append({
                "finding_id":      row["finding_id"],
                "technique_id":    row["technique_id"],
                "event_count":     row["event_count"],
                "correct_label":   row["corrected_label"],
                "correct_label_name": row["corrected_label_name"],
                "analyst":         row["analyst_name"],
                "timestamp":       row["created_at"],
            })

        return training_data

    finally:
        conn.close()


# ============================================
# Section 6: Main - Test
# ============================================

if __name__ == "__main__":
    print("=" * 55)
    print("Task 70: Analyst Feedback Workflow")
    print("=" * 55)

    # Init table
    print("\n[1] Initializing feedback table...")
    init_feedback_table()

    # Get latest finding
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    latest = conn.execute(
        "SELECT * FROM findings ORDER BY hunt_timestamp DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not latest:
        print("❌ No findings in DB!")
        print("   Run app_2.py and start a hunt first.")
        exit()

    finding_id = latest["finding_id"]
    print(f"\n[2] Submitting feedback for finding: {finding_id[:8]}...")

    # Test 1: confirmed
    result1 = submit_feedback(
        finding_id      = finding_id,
        analyst_verdict = "confirmed",
        analyst_notes   = "Verified malicious PowerShell activity",
        analyst_name    = "Sohila",
    )

    # Get stats
    print("\n[3] Getting feedback stats...")
    stats = get_feedback_stats()

    # Export training data
    print("\n[4] Exporting training data...")
    training_data = export_training_data()

    # Save results
    output = {
        "task":      "Task 70 - Analyst Feedback Workflow",
        "status":    "complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "test_feedback": result1,
        "stats":         stats,
        "training_data": training_data,

        "summary": {
            "total_feedback":    stats.get("total_feedback", 0),
            "ml_accuracy":       stats.get("ml_accuracy", "N/A"),
            "training_examples": len(training_data),
        }
    }

    with open("task70_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Saved: task70_results.json")

    print("\n" + "=" * 55)
    print("TASK 70 SUMMARY")
    print("=" * 55)
    print(f"Feedback Table   : ✅")
    print(f"Feedback Saved   : ✅")
    print(f"ML Accuracy      : {stats.get('ml_accuracy', 'N/A')}")
    print(f"Training Examples: {len(training_data)}")
    print(f"API Ready        : ✅")
    print(f"Status           : COMPLETE ✅")
    print("=" * 55)