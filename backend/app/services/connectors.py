"""
services/connectors.py
----------------------
One interface for every execution backend. A connector takes a validated
SigmaRule and returns matches; the campaign engine never needs to know which
backend produced them.

  local     built-in: evaluates the Sigma rule directly against the local
            telemetry store (real EVTX / JSONL events). Always available.
  splunk    real Splunk REST export search. Enabled when SPLUNK_URL and
            SPLUNK_TOKEN (or SPLUNK_USER/SPLUNK_PASSWORD) are set.
  elastic / sentinel / wazuh / fortisiem
            registered so the UI can show them; compile-only until credentials
            + a client are configured (reported honestly as `not_configured`).
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.services import telemetry
from app.services.sigma_engine import SigmaRule, compile_native


@dataclass
class ConnectorResult:
    status: str                    # completed | failed | skipped
    query: str = ""
    events_scanned: int = 0
    matches: list[dict[str, Any]] = field(default_factory=list)   # {"fields":{}, "meta":{}}
    reason: str = ""
    duration_ms: int = 0


class Connector:
    name = "base"
    label = "Base"
    backend = "splunk"

    def configured(self) -> bool:
        return False

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "label": self.label, "configured": self.configured(), "mode": "live" if self.configured() else "not_configured"}

    def run(self, rule: SigmaRule, db: Session, max_hits: int = 500) -> ConnectorResult:
        raise NotImplementedError


class LocalConnector(Connector):
    name, label, backend = "local", "Local telemetry store", "local"

    def configured(self) -> bool:
        return True

    def run(self, rule: SigmaRule, db: Session, max_hits: int = 500) -> ConnectorResult:
        t0 = time.perf_counter()
        query, _ = compile_native(rule, "splunk")
        cat = rule.logsource.get("category")
        svc = rule.logsource.get("service")
        scanned = 0
        matches: list[dict[str, Any]] = []
        for row, fields in telemetry.iter_events(db, cat, svc, rule.logsource.get("product") or None):
            scanned += 1
            if rule.match(fields):
                matches.append({"fields": fields, "meta": {
                    "dedupe_key": row.dedupe_key, "source": row.source, "host": row.host,
                    "timestamp": row.timestamp, "event_id": row.event_id,
                }})
                if len(matches) >= max_hits:
                    break
        return ConnectorResult("completed", query or "", scanned, matches,
                               "" if scanned else "No telemetry of this log source is loaded",
                               int((time.perf_counter() - t0) * 1000))


class SplunkConnector(Connector):
    name, label, backend = "splunk", "Splunk", "splunk"

    def __init__(self):
        self.url = os.environ.get("SPLUNK_URL", "").rstrip("/")
        self.token = os.environ.get("SPLUNK_TOKEN", "")
        self.user = os.environ.get("SPLUNK_USER", "")
        self.password = os.environ.get("SPLUNK_PASSWORD", "")
        self.verify = os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false"
        self.index = os.environ.get("SPLUNK_INDEX", "*")
        # BOTS v3 events are from 2018, so the default window is all time ("0"), not "-30d".
        self.earliest = os.environ.get("SPLUNK_EARLIEST", "0")
        self.timeout = float(os.environ.get("SPLUNK_TIMEOUT", "120"))

    def _auth(self):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        auth = None if self.token else (self.user, self.password)
        return headers, auth

    def test(self) -> dict[str, Any]:
        """Connectivity check used by POST /connectors/splunk/test: server info + event count in the index."""
        if not self.configured():
            return {"ok": False, "reason": "Splunk not configured (set SPLUNK_URL and SPLUNK_TOKEN)"}
        import httpx
        headers, auth = self._auth()
        out: dict[str, Any] = {"ok": False, "url": self.url, "index": self.index}
        try:
            r = httpx.get(f"{self.url}/services/server/info", params={"output_mode": "json"}, headers=headers,
                          auth=auth, verify=self.verify, timeout=15)
            if r.status_code >= 400:
                out["reason"] = f"HTTP {r.status_code}: {r.text[:200]}"
                return out
            out["version"] = r.json()["entry"][0]["content"].get("version")
            q = f"search index={self.index} earliest={self.earliest} | stats count"
            r = httpx.post(f"{self.url}/services/search/jobs/export", headers=headers, auth=auth, verify=self.verify,
                           data={"search": q, "output_mode": "json"}, timeout=60)
            count = None
            for line in r.text.splitlines():
                try:
                    res = json.loads(line).get("result")
                except json.JSONDecodeError:
                    continue
                if res and "count" in res:
                    count = int(res["count"])
            out.update(ok=r.status_code < 400, event_count=count)
            if count == 0:
                out["warning"] = "Index reachable but empty for this time range (check SPLUNK_INDEX / SPLUNK_EARLIEST)."
        except Exception as exc:  # noqa: BLE001
            out["reason"] = f"connection error: {exc}"
        return out

    def configured(self) -> bool:
        return bool(self.url and (self.token or (self.user and self.password)))

    def run(self, rule: SigmaRule, db: Session, max_hits: int = 500) -> ConnectorResult:
        from app.services.sigma_engine import compile_spl
        query = compile_spl(rule, index=self.index, earliest=self.earliest)
        if not self.configured():
            return ConnectorResult("skipped", query, reason="Splunk not configured (set SPLUNK_URL and SPLUNK_TOKEN)")
        t0 = time.perf_counter()
        try:
            import httpx
            headers, auth = self._auth()
            hits: list[dict[str, Any]] = []
            with httpx.stream("POST", f"{self.url}/services/search/jobs/export", headers=headers, auth=auth,
                              data={"search": query, "output_mode": "json", "count": max_hits},
                              verify=self.verify, timeout=self.timeout) as resp:
                if resp.status_code >= 400:
                    body = resp.read().decode("utf-8", "ignore")[:400]
                    return ConnectorResult("failed", query, reason=f"Splunk HTTP {resp.status_code}: {body}",
                                           duration_ms=int((time.perf_counter() - t0) * 1000))
                for line in resp.iter_lines():
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("preview"):      # export streams preview rows before final results
                        continue
                    result = obj.get("result")
                    if result:
                        hits.append({"fields": result, "meta": {
                            "dedupe_key": (result.get("_cd") or "") + "|" + (result.get("_bkt") or "") + "|" + str(result.get("_serial", "")) + "|" + str(result.get("_indextime", "")),
                            "source": result.get("source", "splunk"), "host": result.get("host", ""),
                            "timestamp": result.get("_time", ""), "event_id": str(result.get("EventCode", result.get("EventID", ""))),
                        }})
            return ConnectorResult("completed", query, len(hits), hits, duration_ms=int((time.perf_counter() - t0) * 1000))
        except Exception as exc:  # noqa: BLE001
            return ConnectorResult("failed", query, reason=f"Splunk connection error: {exc}",
                                   duration_ms=int((time.perf_counter() - t0) * 1000))


class CompileOnlyConnector(Connector):
    def __init__(self, name: str, label: str, backend: str, env_flag: str):
        self.name, self.label, self.backend, self._env = name, label, backend, env_flag

    def configured(self) -> bool:
        return bool(os.environ.get(self._env))

    def run(self, rule: SigmaRule, db: Session, max_hits: int = 500) -> ConnectorResult:
        query, err = compile_native(rule, self.backend)
        if err:
            return ConnectorResult("skipped", "", reason=err)
        return ConnectorResult("skipped", query or "", reason=f"{self.label} execution client not configured; query compiled only")


def registry() -> dict[str, Connector]:
    conns: list[Connector] = [
        LocalConnector(), SplunkConnector(),
        CompileOnlyConnector("elastic", "Elastic", "elastic", "ELASTIC_URL"),
        CompileOnlyConnector("sentinel", "Microsoft Sentinel", "sentinel", "SENTINEL_WORKSPACE_ID"),
        CompileOnlyConnector("wazuh", "Wazuh", "wazuh", "WAZUH_URL"),
        CompileOnlyConnector("fortisiem", "FortiSIEM", "fortisiem", "FORTISIEM_URL"),
    ]
    return {c.name: c for c in conns}


def active_connectors() -> list[Connector]:
    """Executable connectors: local always, plus any live-configured SIEM."""
    return [c for c in registry().values() if c.name in ("local", "splunk") and c.configured()]
