# app.py
# Task 65: Backend API Implementation
# =====================================

import json
import uuid
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ============================================
# Section 1: App Setup
# ============================================

app = FastAPI(
    title       = "Autonomous Threat Hunting Platform",
    description = "AI-powered threat hunting API",
    version     = "1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_methods = ["*"],
    allow_headers = ["*"],
)

DB_PATH = "threat_hunting.db"

# ============================================
# Section 2: Database Helper
# ============================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# Section 3: Request Models
# ============================================

class HuntRequest(BaseModel):
    hypothesis:   str
    technique_id: Optional[str] = None
    earliest:     Optional[str] = "-7d"

class VerdictRequest(BaseModel):
    verdict: str
    notes:   Optional[str] = None
    analyst: Optional[str] = None

# ============================================
# Section 4: Hunt Pipeline
# ============================================

def run_hunt_pipeline(hunt_id: str, hypothesis: str, earliest: str):
    """
    الـ pipeline الكامل:
    Step 1: LLM    → Sigma Rule
    Step 2: Sigma  → SPL
    Step 3: Validate SPL
    Step 4: Splunk → Findings
    Step 5: ML     → Triage
    Step 6: Save   → DB
    """
    conn = get_db()

    try:
        # Update status: running
        conn.execute(
            "UPDATE hunts SET status=? WHERE hunt_id=?",
            ("running", hunt_id)
        )
        conn.commit()

        # Step 1: LLM → Sigma Rule
        # TODO: integrate generate_sigma() from LLM README
        sigma_rule = f"# Sigma rule for: {hypothesis[:50]}"

        # Step 2: Sigma → SPL
        # TODO: integrate SplunkConnector from task55_56.py
        spl_query = f"index=* | search {hypothesis[:30]}"

        # Step 3: Validate SPL
        # TODO: integrate validate_spl_query() from task78
        validation_passed = True

        if not validation_passed:
            conn.execute(
                "UPDATE hunts SET status=?, error=? WHERE hunt_id=?",
                ("failed", "SPL validation failed", hunt_id)
            )
            conn.commit()
            return

        # Save sigma + spl
        conn.execute(
            "UPDATE hunts SET sigma_rule=?, spl_query=? WHERE hunt_id=?",
            (sigma_rule, spl_query, hunt_id)
        )
        conn.commit()

        # Step 4: Splunk → Findings
        # TODO: integrate task58_splunk_execution.py
        splunk_events = []

        # Step 5: ML Triage
        # TODO: integrate xgboost_5M_model.json
        triage_label      = 2
        triage_label_name = "NeedsReview"
        triage_confidence = 0.0

        # Step 6: Save Finding
        finding_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO findings
               (finding_id, hunt_id, technique_id,
                event_count, events, hunt_timestamp,
                triage_label, triage_label_name, triage_confidence)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                finding_id,
                hunt_id,
                "UNKNOWN",
                len(splunk_events),
                json.dumps(splunk_events),
                datetime.now(timezone.utc).isoformat(),
                triage_label,
                triage_label_name,
                triage_confidence,
            )
        )

        # Update status: completed
        conn.execute(
            "UPDATE hunts SET status=?, completed_at=? WHERE hunt_id=?",
            ("completed", datetime.now(timezone.utc).isoformat(), hunt_id)
        )
        conn.commit()

    except Exception as e:
        conn.execute(
            "UPDATE hunts SET status=?, error=? WHERE hunt_id=?",
            ("failed", str(e), hunt_id)
        )
        conn.commit()

    finally:
        conn.close()

# ============================================
# Section 5: API Routes
# ============================================

@app.get("/api/health")
def health():
    return {
        "status":    "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/hunt/start")
async def start_hunt(req: HuntRequest, background_tasks: BackgroundTasks):
    hunt_id = str(uuid.uuid4())
    conn    = get_db()
    try:
        conn.execute(
            """INSERT INTO hunts
               (hunt_id, hypothesis, technique_id, status, created_at)
               VALUES (?,?,?,?,?)""",
            (
                hunt_id,
                req.hypothesis,
                req.technique_id or "UNKNOWN",
                "pending",
                datetime.now(timezone.utc).isoformat(),
            )
        )
        conn.commit()

        background_tasks.add_task(
            run_hunt_pipeline,
            hunt_id,
            req.hypothesis,
            req.earliest or "-7d",
        )

        return {
            "hunt_id": hunt_id,
            "status":  "pending",
            "message": "Hunt started successfully",
        }
    finally:
        conn.close()


@app.get("/api/hunt/{hunt_id}/status")
def get_hunt_status(hunt_id: str):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM hunts WHERE hunt_id=?",
            (hunt_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Hunt {hunt_id} not found")

        return dict(row)
    finally:
        conn.close()


@app.get("/api/hunt/{hunt_id}/findings")
def get_findings(hunt_id: str):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE hunt_id=?",
            (hunt_id,)
        ).fetchall()

        findings = []
        for row in rows:
            f = dict(row)
            if f.get("events"):
                f["events"] = json.loads(f["events"])
            findings.append(f)

        return {
            "hunt_id":        hunt_id,
            "total_findings": len(findings),
            "findings":       findings,
        }
    finally:
        conn.close()


@app.post("/api/findings/{finding_id}/verdict")
def submit_verdict(finding_id: str, req: VerdictRequest):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM findings WHERE finding_id=?",
            (finding_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Finding {finding_id} not found")

        valid_verdicts = ["confirmed", "rejected", "escalated"]
        if req.verdict not in valid_verdicts:
            raise HTTPException(
                400,
                f"verdict must be one of: {valid_verdicts}"
            )

        verdict_id = str(uuid.uuid4())
        now        = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """INSERT INTO verdicts
               (verdict_id, finding_id, hunt_id,
                verdict, notes, analyst, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                verdict_id,
                finding_id,
                row["hunt_id"],
                req.verdict,
                req.notes,
                req.analyst,
                now,
            )
        )

        conn.execute(
            "UPDATE findings SET analyst_verdict=? WHERE finding_id=?",
            (req.verdict, finding_id)
        )
        conn.commit()

        return {
            "verdict_id": verdict_id,
            "finding_id": finding_id,
            "verdict":    req.verdict,
            "created_at": now,
        }
    finally:
        conn.close()


@app.get("/api/hunts")
def list_hunts():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM hunts ORDER BY created_at DESC"
        ).fetchall()
        return {
            "total": len(rows),
            "hunts": [dict(row) for row in rows],
        }
    finally:
        conn.close()


@app.get("/api/report/{hunt_id}")
def get_report(hunt_id: str):
    conn = get_db()
    try:
        hunt = conn.execute(
            "SELECT * FROM hunts WHERE hunt_id=?",
            (hunt_id,)
        ).fetchone()

        if not hunt:
            raise HTTPException(404, f"Hunt {hunt_id} not found")

        findings_rows = conn.execute(
            "SELECT * FROM findings WHERE hunt_id=?",
            (hunt_id,)
        ).fetchall()

        findings = []
        triage_counts = {
            "FalsePositive": 0,
            "TruePositive":  0,
            "NeedsReview":   0,
        }

        for row in findings_rows:
            f = dict(row)
            if f.get("events"):
                f["events"] = json.loads(f["events"])
            findings.append(f)
            label = f.get("triage_label_name", "NeedsReview")
            if label in triage_counts:
                triage_counts[label] += 1

        return {
            "hunt_id":        hunt_id,
            "hypothesis":     hunt["hypothesis"],
            "technique_id":   hunt["technique_id"],
            "sigma_rule":     hunt["sigma_rule"],
            "spl_query":      hunt["spl_query"],
            "status":         hunt["status"],
            "created_at":     hunt["created_at"],
            "completed_at":   hunt["completed_at"],
            "findings":       findings,
            "triage_summary": triage_counts,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
        }
    finally:
        conn.close()


# ============================================
# Section 6: Run Server
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)