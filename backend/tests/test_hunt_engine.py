"""Unit + end-to-end tests for the real hunt pipeline (no network needed)."""
import json
import os
import tempfile
from pathlib import Path

import pytest

from app.services.sigma_engine import compile_spl, parse_rule, validate_rule

RULE = """title: Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
tags: [attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  img:
    Image|endswith: '\\powershell.exe'
  cmd:
    CommandLine|contains: [' -enc ', ' -EncodedCommand']
  filter:
    ParentImage|endswith: '\\sccm.exe'
  condition: img and cmd and not filter
level: high
"""


def test_match_and_filter():
    r, issues = parse_rule(RULE)
    assert r and not issues
    assert r.match({"Image": "C:\\x\\POWERSHELL.EXE", "CommandLine": "ps -enc AAA"})
    assert not r.match({"Image": "C:\\x\\powershell.exe", "CommandLine": "ps -enc AAA", "ParentImage": "C:\\sccm.exe"})
    assert not r.match({"Image": "C:\\x\\cmd.exe", "CommandLine": "-enc"})


def test_spl_compiles():
    r, _ = parse_rule(RULE)
    spl = compile_spl(r)
    assert "| where" in spl and "NOT" in spl and "powershell.exe" in spl


def test_gate_blocks_placeholder_and_aggregation():
    bad = "title: x\nlogsource: {product: windows}\ndetection:\n  s:\n    CommandLine|contains: REPLACE_WITH_INDICATOR\n  condition: s\n"
    assert not validate_rule(bad)["executable"]
    agg = "title: x\nlogsource: {product: windows}\ndetection:\n  s:\n    a: 1\n  condition: s | count() > 5\n"
    assert parse_rule(agg)[0] is None


def test_unsupported_modifier_is_reported_not_ignored():
    y = "title: x\nlogsource: {product: windows}\ndetection:\n  s:\n    Field|cidr: 10.0.0.0/8\n  condition: s\n"
    r, issues = parse_rule(y)
    assert r is None and issues[0].code == "unsupported_feature"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("THREATHUNT_AUTH_DB_PATH", str(tmp_path / "auth.db"))
    for m in [m for m in list(__import__("sys").modules) if m.startswith("app.")]:
        del __import__("sys").modules[m]
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.database import SessionLocal
    from app.models.attack import AttackTechnique
    with SessionLocal() as session:
        session.add(AttackTechnique(
            stix_id="attack-pattern--11111111-1111-1111-1111-111111111111",
            attack_id="T1059.001", name="PowerShell",
        ))
        session.commit()
    return TestClient(app)


def _login(c, email="analyst@enterprise.local"):
    t = c.post("/api/auth/login", json={"email": email, "password": "threathunt"}).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}


def test_auth_required_and_monitor_read_only(client):
    assert client.get("/api/campaigns").status_code == 401
    mon = _login(client, "monitor@enterprise.local")
    assert client.get("/api/campaigns", headers=mon).status_code == 200
    assert client.post("/api/campaigns", headers=mon, json={"name": "x"}).status_code == 403


def test_full_campaign_flow_with_jsonl_telemetry(client, tmp_path):
    H = _login(client)
    admin = _login(client, "admin@enterprise.local")
    ev = {"EventID": "1", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01",
          "TimeCreated": "2026-09-01T10:00:00Z", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "CommandLine": "powershell.exe -nop -w hidden -enc JABQAHIAbwBnAHIAZQBzAHMA", "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
          "User": "CORP\\bob", "ProcessId": "4242"}
    f = tmp_path / "ev.jsonl"
    f.write_text(json.dumps(ev) + "\n" + json.dumps({**ev, "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad"}) + "\n")
    r = client.post("/api/telemetry/ingest", headers=admin, json={"kind": "jsonl", "path": str(f)})
    assert r.status_code == 200 and r.json()["added"] == 2
    assert client.post("/api/telemetry/ingest", headers=admin, json={"kind": "jsonl", "path": str(f)}).json()["added"] == 0  # idempotent

    cid = client.post("/api/campaigns", headers=H, json={"name": "t", "technique_ids": ["T1059.001"]}).json()["id"]
    run = client.post(f"/api/campaigns/{cid}/run", headers=H, json={}).json()
    assert run["status"] == "completed" and run["total_findings"] >= 1
    total = run["total_findings"]
    assert client.post(f"/api/campaigns/{cid}/run", headers=H, json={}).json()["total_findings"] == total  # rerun is idempotent

    execs = client.get(f"/api/campaigns/{cid}/executions", headers=H).json()["items"]
    assert execs and all(e["events_scanned"] >= 0 for e in execs) and any(e["hits"] for e in execs)
    stages = {s["id"]: s for s in client.get(f"/api/campaigns/{cid}/pipeline", headers=H).json()["stages"]}
    assert stages["execute"]["status"] == "done"

    fid = client.get(f"/api/campaigns/{cid}", headers=H).json()["findings"][0]["finding_id"]
    finding = client.get(f"/api/findings/{fid}", headers=H).json()
    assert isinstance(finding["processes"][0], dict) and finding["triage"]["top_factors"]
    assert client.post(f"/api/findings/{fid}/verdict", headers=H, json={"verdict": "false_positive"}).status_code == 200
    assert '"label": 0' in client.get("/api/findings/feedback/export", headers=H).text
    assert "Hunt report" in client.get(f"/api/campaigns/{cid}/report", headers=H).text
