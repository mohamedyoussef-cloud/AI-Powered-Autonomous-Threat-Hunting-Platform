"""Tests for the xgboost_te_v3_1 triage integration (contract: ML_INTEGRATION_GUIDE.md)."""
import pytest

from app.services import ml_triage as mt
from app.services.triage import apply_ml

FULL = {"Category": "Execution", "MitreTechniques": "T1059;T1059.001", "EntityType": "Process",
        "EvidenceRole": "Impacted", "OSFamily": "5", "OSVersion": "66", "CountryCode": "31", "State": "6",
        "City": "10630", "AlertTitle": "a", "DetectorId": "b", "ApplicationName": "c", "ThreatFamily": "d",
        "Timestamp": "2024-06-04T10:20:00Z", "DeviceId": "d1", "FileName": "a.exe", "IpAddress": "1.2.3.4"}


@pytest.fixture(scope="module")
def engine():
    e = mt.get_engine()
    if not e.ensure_loaded():
        pytest.skip(f"ML bundle not available: {e.error}")
    return e


def test_bundle_integrity_and_feature_count(engine):
    assert engine.integrity["status"] == "ok"
    assert len(engine.feature_names) == 103


def test_full_record_probabilities_and_policy(engine):
    r = engine.score_records([FULL, FULL | {"Category": "InitialAccess", "MitreTechniques": "T1566"}])
    for x in r:
        assert x["available"] and x["triage_source"] == "ml_model"
        s = x["probability_true_positive"] + x["probability_benign_positive"] + x["probability_false_positive"]
        assert abs(s - 1) < 1e-4
        assert x["autonomous_action"] is False
        if x["predicted_class"] == "TRUE_POSITIVE" and x["probability_true_positive"] < 0.5:
            assert x["route"] == "NEEDS_REVIEW"
        if x["predicted_class"] == "BENIGN_POSITIVE":
            assert x["route"] == "BENIGN_REVIEW_QUEUE"      # BP is never auto-closed or merged with FP


def test_sparse_platform_finding_is_explicitly_unavailable(engine):
    out = mt.ml_triage_for_match({"Image": "a.exe", "User": "u", "Computer": "H"},
                                 {"timestamp": "2020-01-01T00:00:00Z", "host": "H"},
                                 ["attack.execution", "attack.t1059.001"], ["T1059.001"])
    assert out["available"] is False and out["triage_source"] == "heuristic_fallback"
    assert out["coverage"]["present"] == ["Category", "MitreTechniques"]
    assert "probability_true_positive" not in out          # fallback is never presented as ML


def test_adapter_does_not_invent_fields():
    rec = mt.build_guide_record({"Image": "x.exe"}, {}, ["attack.persistence"], ["T1547.001"])
    assert rec["Category"] == "Persistence" and rec["MitreTechniques"] == "T1547.001"
    for k in ("AlertTitle", "DetectorId", "ThreatFamily", "EntityType", "OSFamily", "CountryCode"):
        assert k not in rec


def test_missing_bundle_falls_back_without_crashing(monkeypatch):
    monkeypatch.setenv("ML_TRIAGE_BUNDLE_DIR", "/nonexistent")
    e = mt.MLTriageEngine()
    r = e.score_records([FULL])[0]
    assert r["available"] is False and "bundle unavailable" in r["reason"]


def test_mode_off(monkeypatch):
    monkeypatch.setenv("ML_TRIAGE_MODE", "off")
    assert mt.MLTriageEngine().score_records([FULL])[0]["available"] is False


def test_apply_ml_semantics():
    heur = {"model": "explainable_logistic_v1", "risk_score": 70.0, "threat_probability": 0.7, "label": "medium",
            "route": "analyst_review", "top_factors": [{"factor": "x", "impact": 1}], "features": {"a": 1}}
    unavailable = mt.MLTriageEngine._unavailable("x", {})
    t = apply_ml(dict(heur), unavailable)
    assert t["triage_source"] == "heuristic_fallback" and t["risk_score"] == 70.0 and t["features"] == {"a": 1}
    fp_heavy = {"available": True, "model_version": "xgboost_te_v3_1", "probability_true_positive": 0.05,
                "probability_benign_positive": 0.1, "probability_false_positive": 0.85,
                "predicted_class": "FALSE_POSITIVE", "route": "FALSE_POSITIVE_REVIEW_QUEUE"}
    t = apply_ml(dict(heur), fp_heavy)
    assert t["triage_source"] == "ml_model" and t["risk_score"] == 5.0      # high FP prob must NOT raise risk
    assert t["route"] == "low_priority" and t["heuristic_reference"]["risk_score"] == 70.0 and t["features"] == {"a": 1}


def test_endpoint_rejects_verdict_input():
    from fastapi.testclient import TestClient
    from app.core.security import require_analyst, require_user
    from app.main import app
    app.dependency_overrides[require_analyst] = lambda: {"email": "t@t"}
    app.dependency_overrides[require_user] = lambda: {"email": "t@t"}
    try:
        c = TestClient(app)
        assert c.post("/api/ml-triage/score", json={"records": [{"Category": "Execution", "IncidentGrade": "TruePositive"}]}).status_code == 400
        assert c.post("/api/ml-triage/score", json={"records": []}).status_code == 400
        assert c.get("/api/ml-triage/status").json()["model_version"] == "xgboost_te_v3_1"
    finally:
        app.dependency_overrides.clear()
