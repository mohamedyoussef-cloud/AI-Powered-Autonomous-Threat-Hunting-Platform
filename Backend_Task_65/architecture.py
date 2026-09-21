# task65_architecture.py
# Task 65: Backend Architecture and API Design
# ============================================

import json
import uuid
import sqlite3
from datetime import datetime, timezone

# ============================================
# Section 1: Architecture Overview
# ============================================

ARCHITECTURE = {
    "platform": "Autonomous Threat Hunting Platform",
    "version":  "1.0.0",

    "pipeline": [
        "1. Analyst writes hypothesis",
        "2. LLM generates Sigma rule",
        "3. pySigma converts Sigma to SPL",
        "4. Validation Gate checks SPL",
        "5. Splunk executes SPL and returns Findings",
        "6. ML Triage labels findings",
        "7. Analyst reviews and gives verdict",
        "8. Hunt Report generated",
    ],

    "components": {
        "LLM":        "Qwen3-8B fine-tuned → Sigma rule",
        "SIEM":       "pySigma → SPL query",
        "Validation": "Query Validation Gate",
        "Splunk":     "Hunt execution → raw findings",
        "ML":         "XGBoost triage → TP/FP/NeedsReview",
        "Backend":    "FastAPI → orchestrates everything",
        "Frontend":   "React UI → analyst interface",
    }
}

# ============================================
# Section 2: Database Schema
# ============================================

DB_PATH = "threat_hunting.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS hunts (
    hunt_id        TEXT PRIMARY KEY,
    hypothesis     TEXT NOT NULL,
    technique_id   TEXT,
    technique_name TEXT,
    tactic         TEXT,
    sigma_rule     TEXT,
    spl_query      TEXT,
    status         TEXT DEFAULT 'pending',
    created_at     TEXT NOT NULL,
    completed_at   TEXT,
    error          TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id        TEXT PRIMARY KEY,
    hunt_id           TEXT NOT NULL,
    technique_id      TEXT,
    event_count       INTEGER DEFAULT 0,
    events            TEXT,
    hunt_timestamp    TEXT,
    triage_label      INTEGER,
    triage_label_name TEXT,
    triage_confidence REAL,
    analyst_verdict   TEXT,
    FOREIGN KEY (hunt_id) REFERENCES hunts(hunt_id)
);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    hunt_id    TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    notes      TEXT,
    analyst    TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
"""

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"✅ Database initialized: {DB_PATH}")
    return True

# ============================================
# Section 3: API Endpoints Design
# ============================================

API_DESIGN = {
    "base_url": "http://localhost:8000",
    "version":  "v1",

    "endpoints": [
        {
            "id":          1,
            "method":      "POST",
            "path":        "/api/hunt/start",
            "description": "Start a new threat hunt",
            "request": {
                "hypothesis":   "string (required)",
                "technique_id": "string (optional)",
                "earliest":     "string (optional, default=-7d)",
            },
            "response": {
                "hunt_id": "UUID",
                "status":  "pending",
            },
        },
        {
            "id":          2,
            "method":      "GET",
            "path":        "/api/hunt/{hunt_id}/status",
            "description": "Get current hunt status",
            "response": {
                "hunt_id":      "UUID",
                "status":       "pending|running|completed|failed",
                "hypothesis":   "string",
                "technique_id": "string",
                "created_at":   "timestamp",
                "completed_at": "timestamp|null",
                "error":        "string|null",
            },
        },
        {
            "id":          3,
            "method":      "GET",
            "path":        "/api/hunt/{hunt_id}/findings",
            "description": "Get all findings for a hunt",
            "response": {
                "hunt_id":        "UUID",
                "total_findings": "int",
                "findings":       "list[HuntFinding]",
            },
        },
        {
            "id":          4,
            "method":      "POST",
            "path":        "/api/findings/{finding_id}/verdict",
            "description": "Submit analyst verdict",
            "request": {
                "verdict": "confirmed|rejected|escalated",
                "notes":   "string (optional)",
                "analyst": "string (optional)",
            },
            "response": {
                "verdict_id": "UUID",
                "finding_id": "UUID",
                "verdict":    "string",
                "created_at": "timestamp",
            },
        },
        {
            "id":          5,
            "method":      "GET",
            "path":        "/api/hunts",
            "description": "List all hunts",
            "response": {
                "total": "int",
                "hunts": "list[HuntSummary]",
            },
        },
        {
            "id":          6,
            "method":      "GET",
            "path":        "/api/report/{hunt_id}",
            "description": "Generate hunt report",
            "response": {
                "hunt_id":        "UUID",
                "hypothesis":     "string",
                "sigma_rule":     "string",
                "spl_query":      "string",
                "findings":       "list[HuntFinding]",
                "triage_summary": "dict",
                "generated_at":   "timestamp",
            },
        },
        {
            "id":          7,
            "method":      "GET",
            "path":        "/api/health",
            "description": "Health check",
            "response": {
                "status":    "ok",
                "timestamp": "timestamp",
            },
        },
    ],
}

# ============================================
# Section 4: Service Boundaries
# ============================================

SERVICES = {
    "HypothesisService": {
        "description": "Calls LLM to generate Sigma rule",
        "input":       "hypothesis (str)",
        "output":      "sigma_rule (str)",
        "uses":        "generate_sigma() from LLM README",
        "task":        "Tasks 50-52",
        "status":      "✅ Ready",
    },
    "SPLService": {
        "description": "Converts Sigma to SPL and validates",
        "input":       "sigma_rule (str)",
        "output":      "spl_query (str)",
        "uses":        "SplunkConnector + validate_spl_query()",
        "task":        "Tasks 55-56-78",
        "status":      "✅ Ready",
    },
    "SplunkService": {
        "description": "Executes SPL on Splunk and returns findings",
        "input":       "spl_query (str)",
        "output":      "list[HuntFinding]",
        "uses":        "task58_splunk_execution.py",
        "task":        "Task 58",
        "status":      "⏳ Awaiting Splunk",
    },
    "TriageService": {
        "description": "Runs XGBoost ML triage on findings",
        "input":       "list[HuntFinding]",
        "output":      "list[HuntFinding] with triage_label",
        "uses":        "xgboost_5M_model.json",
        "task":        "Tasks 63-64",
        "status":      "✅ Ready",
    },
    "ReportService": {
        "description": "Generates hunt report from all components",
        "input":       "hunt_id (str)",
        "output":      "HuntReport",
        "uses":        "DB findings + verdicts",
        "task":        "Task 81",
        "status":      "⏳ Pending",
    },
}

# ============================================
# Section 5: Save Design + Main
# ============================================

def save_design():
    output = {
        "task":      "Task 65 - Backend Architecture and API Design",
        "status":    "complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "architecture": ARCHITECTURE,
        "api_design":   API_DESIGN,
        "services":     SERVICES,

        "tech_stack": {
            "framework":  "FastAPI (Python)",
            "database":   "SQLite",
            "api_style":  "REST",
            "background": "FastAPI BackgroundTasks",
        },

        "summary": {
            "total_endpoints": len(API_DESIGN["endpoints"]),
            "total_services":  len(SERVICES),
            "db_tables":       3,
            "status":          "Architecture defined ✅",
        },
    }

    with open("task65_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print("✅ Saved: task65_results.json")
    return output


if __name__ == "__main__":
    print("=" * 55)
    print("Task 65: Backend Architecture and API Design")
    print("=" * 55)

    print("\n[1] Initializing database...")
    init_db()

    print("\n[2] Saving architecture design...")
    result = save_design()

    print("\n" + "=" * 55)
    print("TASK 65 SUMMARY")
    print("=" * 55)
    print(f"API Endpoints : {result['summary']['total_endpoints']} ✅")
    print(f"Services      : {result['summary']['total_services']} ✅")
    print(f"DB Tables     : {result['summary']['db_tables']} ✅")
    print(f"Database      : {DB_PATH} ✅")
    print(f"Design file   : task65_results.json ✅")
    print("Status        : COMPLETE ✅")
    print("=" * 55)