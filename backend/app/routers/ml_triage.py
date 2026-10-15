"""
routers/ml_triage.py
--------------------
Status and direct-scoring endpoints for the frozen XGBoost TE-v3.1 triage model.
Output is analyst-assisted prioritisation; it is never a final verdict.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.core.security import require_analyst, require_user
from app.services.ml_triage import BATCH_LIMIT, SEMANTIC_FIELDS, get_engine

router = APIRouter(prefix="/ml-triage", tags=["ml-triage"])


@router.get("/status")
def ml_status(_=Depends(require_user)):
    return get_engine().status()


@router.post("/score")
def ml_score(payload: dict, _=Depends(require_analyst)):
    """Score GUIDE-schema alert records: {"records": [{...}], "enforce_coverage": true}.

    Fields (all optional, absent = missing, never invented): Category, MitreTechniques, EntityType,
    EvidenceRole, ResourceType, Roles, OSFamily, OSVersion, AntispamDirection, CountryCode, State, City,
    AlertTitle, DetectorId, ApplicationName, ThreatFamily, Timestamp and the presence inputs
    IpAddress, Url, Sha256, DeviceId, AccountSid, AccountUpn, AccountObjectId, NetworkMessageId,
    EmailClusterId, RegistryKey, FileName, FolderPath. Analyst verdict/history is not accepted as input.
    """
    records = payload.get("records")
    if not isinstance(records, list) or not records or not all(isinstance(r, dict) for r in records):
        raise HTTPException(400, "records must be a non-empty list of objects")
    if len(records) > BATCH_LIMIT:
        raise HTTPException(400, f"at most {BATCH_LIMIT} records per request")
    banned = {"IncidentGrade", "LastVerdict", "analyst_verdict", "verdict"}
    if any(banned & set(r) for r in records):
        raise HTTPException(400, "verdict/label fields must not be supplied as model input")
    results = get_engine().score_records(records, enforce_coverage=bool(payload.get("enforce_coverage", True)))
    return {"model_version": "xgboost_te_v3_1", "coverage_fields": SEMANTIC_FIELDS, "results": results}
