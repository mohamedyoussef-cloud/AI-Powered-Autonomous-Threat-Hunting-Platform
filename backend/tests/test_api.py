"""
tests/test_api.py
--------------------
Integration tests against the real running database (the same Postgres
instance load_pipeline_data.py populated) via FastAPI's TestClient. These
are not mocked — they exercise the real SQLAlchemy queries and real
pySigma validation in the generator endpoint.

Run after `python scripts/init_db.py && python scripts/load_pipeline_data.py`:
    pytest tests/ -v
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)
# v3.1: the API requires a bearer token. Log in once as the seeded analyst.
_tok = client.post("/api/auth/login", json={"email": "analyst@enterprise.local", "password": "threathunt"}).json().get("access_token", "")
client.headers.update({"Authorization": f"Bearer {_tok}"})


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_attack_techniques_list():
    r = client.get("/api/attack/techniques")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert all("attack_id" in t and "tactics" in t for t in data)


def test_attack_coverage_matrix_shape():
    r = client.get("/api/attack/coverage")
    assert r.status_code == 200
    data = r.json()
    assert "tactics" in data and "cells" in data
    assert 0 <= data["coverage_pct"] <= 100
    for cell in data["cells"]:
        assert cell["rule_count"] >= 0


def test_sigma_rules_pagination():
    r = client.get("/api/sigma/rules?page=1&page_size=2")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 1
    assert len(data["items"]) <= 2


def test_sigma_rules_quarantine_filter_excludes_others():
    r = client.get("/api/sigma/rules?quarantine_category=deprecated")
    assert r.status_code == 200
    data = r.json()
    assert all(item["quarantine_category"] == "deprecated" for item in data["items"])


def test_sigma_rule_detail_404_for_unknown_id():
    r = client.get("/api/sigma/rules/does-not-exist")
    assert r.status_code == 404


def test_sigma_facets_are_nonempty_lists():
    r = client.get("/api/sigma/facets")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["quarantine_categories"], list)


def test_findings_list_and_summary():
    r = client.get("/api/findings")
    assert r.status_code == 200
    assert "items" in r.json()

    r2 = client.get("/api/findings/stats/summary")
    assert r2.status_code == 200
    assert "by_label" in r2.json()


def test_pipeline_status():
    r = client.get("/api/pipeline/status")
    if r.status_code == 404:
        assert r.json()["detail"] == "No pipeline run has been loaded yet"
        return
    assert r.status_code == 200
    data = r.json()
    assert data["overall_status"] in ("SUCCESS", "COMPLETED_WITH_WARNINGS", "FAILED")
    assert isinstance(data["stages"], list)
    assert isinstance(data["quality_gates"], list)


def test_generator_discloses_source_and_returns_validation_gate():
    """Regression test for the real bug caught during manual testing:
    the template generator originally emitted a non-UUID `id:` field,
    which real pySigma correctly rejected. This must never regress."""
    r = client.post(
        "/api/generator/generate-rule",
        json={"hypothesis_text": "detect powershell with an encoded -enc command", "target_platform": "windows"},
    )
    assert r.status_code == 200
    data = r.json()
    assert "keyword template" in data["warning"].lower()
    assert "gate" in data
    assert isinstance(data["gate"]["executable"], bool)
    assert "template_v0" in data["generation_method"]
    # Confirm the id: line really is a valid UUID (regex-shaped check).
    import re
    m = re.search(r"^id: ([0-9a-f-]{36})$", data["generated_yaml"], re.MULTILINE)
    assert m, "generated rule must contain a UUID-shaped id: field"


def test_generator_response_never_omits_the_template_warning():
    """No generator response should ever look like validated LLM output —
    the warning disclosure is mandatory on every response."""
    r = client.post(
        "/api/generator/generate-rule",
        json={"hypothesis_text": "some totally generic hunting idea with no keyword match"},
    )
    assert r.status_code == 200
    assert "template" in r.json()["warning"].lower()


def test_datasets_catalog_reads_real_source_registry():
    """Regression coverage for the Dataset Manager screen: every active
    (non-excluded) source must carry a real license and intended-use
    string straight from config/sources.yaml — never a placeholder."""
    r = client.get("/api/datasets")
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 4  # attack, sigma, evtx, bots (darpa excluded)

    active = [d for d in data if not d["excluded"]]
    for d in active:
        assert d["license"] and d["license"] != "N/A"
        assert d["intended_platform_use"]
        assert d["health_status"]  # never blank — "not yet parsed" is the honest floor

    excluded = [d for d in data if d["excluded"]]
    assert any(d["source_id"] == "darpa" for d in excluded)


def test_datasets_connections_never_claims_llm_is_live_without_config():
    """The Hypothesis Engine connection must report not_configured unless
    a real LLM is wired in — this is the exact honesty guarantee the
    platform promises on the Rule Generator screen."""
    r = client.get("/api/datasets/connections")
    assert r.status_code == 200
    conns = {c["connection_id"]: c for c in r.json()}
    assert "rule_generator_llm" in conns
    assert conns["rule_generator_llm"]["status"] == "not_configured"
    assert "template_v0" in conns["rule_generator_llm"]["detail"]

    # pySigma, by contrast, IS real and must say so.
    assert conns["pysigma_validator"]["status"] == "live"
