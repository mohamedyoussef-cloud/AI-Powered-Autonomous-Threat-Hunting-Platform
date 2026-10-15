"""
services/telemetry.py
---------------------
The local hunt backend's event store. Events are normalized to Sigma field
names (Image, CommandLine, ParentImage, ...) so a Sigma rule can run on
them unchanged.

Ingestion sources (all idempotent, dedupe by content hash):
  * local .evtx file or directory        -> ingest_evtx_path()
  * public EVTX-ATTACK-SAMPLES download  -> ingest_github_sample()  (cached on disk)
  * normalized JSONL / JSONL.GZ          -> ingest_jsonl()

Nothing here fabricates data: an empty store yields empty hunts, and the
campaign engine reports that explicitly instead of producing findings.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.execution import TelemetryEvent

EVTX_REPO_RAW = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"
CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "evtx_cache"
DEFAULT_SAMPLES = [
    s.strip() for s in os.environ.get(
        "EVTX_SAMPLE_PATHS",
        "Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx,"
        "Execution/exec_sysmon_1_lolbin_pcalua.evtx",
    ).split(",") if s.strip()
]
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

SYSMON_CATEGORY = {
    "1": "process_creation", "2": "file_change", "3": "network_connection",
    "5": "process_termination", "6": "driver_load", "7": "image_load",
    "8": "create_remote_thread", "9": "raw_access_thread", "10": "process_access",
    "11": "file_event", "12": "registry_add", "13": "registry_set", "14": "registry_event",
    "15": "create_stream_hash", "17": "pipe_created", "18": "pipe_created",
    "19": "wmi_event", "20": "wmi_event", "21": "wmi_event", "22": "dns_query",
    "23": "file_delete", "25": "process_tampering",
}
CHANNEL_SERVICE = {
    "security": "security", "system": "system", "application": "application",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell-classic",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-windows defender/operational": "windefend",
    "microsoft-windows-wmi-activity/operational": "wmi",
}
# alias map used for loosely-structured JSONL inputs
FIELD_ALIASES = {
    "image": "Image", "command_line": "CommandLine", "commandline": "CommandLine",
    "parent_image": "ParentImage", "parent_command_line": "ParentCommandLine",
    "user": "User", "process_id": "ProcessId", "process_guid": "ProcessGuid",
    "destination_ip": "DestinationIp", "destination_port": "DestinationPort",
    "target_filename": "TargetFilename", "target_object": "TargetObject",
    "script_block_text": "ScriptBlockText",
}


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------
def normalize_evtx_xml(xml: str, source: str) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    sysn = root.find("e:System", _NS)
    if sysn is None:
        return None

    def sv(tag: str) -> str:
        n = sysn.find(f"e:{tag}", _NS)
        return (n.text or "").strip() if n is not None else ""

    tc = sysn.find("e:TimeCreated", _NS)
    provider = sysn.find("e:Provider", _NS)
    channel = sv("Channel")
    eid = sv("EventID")
    fields: dict[str, Any] = {}
    for parent in (root.find("e:EventData", _NS), root.find("e:UserData", _NS)):
        if parent is None:
            continue
        for item in parent.iter():
            name = item.attrib.get("Name")
            if name and (item.text is not None):
                fields[name] = item.text
    is_sysmon = "sysmon" in channel.lower() or (provider is not None and "sysmon" in provider.attrib.get("Name", "").lower())
    service = "sysmon" if is_sysmon else CHANNEL_SERVICE.get(channel.lower(), re.sub(r"[^a-z0-9]+", "-", channel.lower()).strip("-") or None)
    category = SYSMON_CATEGORY.get(eid) if is_sysmon else None
    if not category and service == "security" and eid == "4688":
        category = None  # real Sigma maps 4688 via field renames; kept as security-service events
    fields.update({
        "EventID": eid, "Computer": sv("Computer"), "Channel": channel,
        "TimeCreated": tc.attrib.get("SystemTime", "") if tc is not None else "",
        "Provider": provider.attrib.get("Name", "") if provider is not None else "",
    })
    return {
        "product": "windows", "category": category, "service": service,
        "event_id": eid, "host": sv("Computer"), "timestamp": fields["TimeCreated"],
        "fields": fields, "source": source,
    }


def normalize_json_event(obj: dict[str, Any], source: str) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    base: dict[str, Any] = {}
    for key in ("fields", "event_data", "EventData", "raw"):
        if isinstance(obj.get(key), dict):
            base.update(obj[key])
    for k, v in obj.items():
        if not isinstance(v, (dict, list)):
            base.setdefault(k, v)
    fields = {FIELD_ALIASES.get(str(k).lower(), k): v for k, v in base.items()}
    eid = str(fields.get("EventID") or fields.get("event_id") or "")
    channel = str(fields.get("Channel") or fields.get("channel") or "")
    is_sysmon = "sysmon" in channel.lower() or "sysmon" in str(obj.get("provider", "")).lower()
    category = obj.get("category") or (SYSMON_CATEGORY.get(eid) if is_sysmon or "Image" in fields else None)
    service = obj.get("service") or ("sysmon" if is_sysmon else CHANNEL_SERVICE.get(channel.lower()))
    host = str(fields.get("Computer") or fields.get("host") or fields.get("hostname") or "")
    ts = str(fields.get("TimeCreated") or fields.get("timestamp") or fields.get("UtcTime") or "")
    fields.update({"EventID": eid, "Computer": host, "TimeCreated": ts})
    return {"product": str(obj.get("product") or "windows").lower(), "category": category, "service": service,
            "event_id": eid, "host": host, "timestamp": ts, "fields": fields, "source": source}


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------
def _dedupe_key(ev: dict[str, Any]) -> str:
    payload = json.dumps([ev["source"], ev["event_id"], ev["timestamp"], ev["host"], ev["fields"]], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:40]


def _store(db: Session, events: Iterable[dict[str, Any]], kind: str, batch: int = 500) -> dict[str, int]:
    added = skipped = 0
    pending: list[TelemetryEvent] = []
    seen: set[str] = set()

    def flush():
        nonlocal added, skipped, pending
        if not pending:
            return
        keys = [p.dedupe_key for p in pending]
        existing = {k for (k,) in db.query(TelemetryEvent.dedupe_key).filter(TelemetryEvent.dedupe_key.in_(keys)).all()}
        fresh = [p for p in pending if p.dedupe_key not in existing]
        skipped += len(pending) - len(fresh)
        db.add_all(fresh)
        added += len(fresh)
        db.flush()
        pending = []

    for ev in events:
        key = _dedupe_key(ev)
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        pending.append(TelemetryEvent(
            dedupe_key=key, source=ev["source"], source_kind=kind, product=ev["product"],
            category=ev["category"], service=ev["service"], event_id=ev["event_id"], host=ev["host"],
            timestamp=ev["timestamp"], fields_json=json.dumps(ev["fields"], default=str, ensure_ascii=False),
        ))
        if len(pending) >= batch:
            flush()
    flush()
    db.commit()
    return {"added": added, "skipped_duplicates": skipped}


def _iter_evtx(path: Path, source: str) -> Iterator[dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as exc:
        raise RuntimeError("python-evtx is required for EVTX ingestion (pip install python-evtx)") from exc
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                ev = normalize_evtx_xml(record.xml(), source)
            except Exception:  # noqa: BLE001 - one corrupt record must not abort the file
                continue
            if ev:
                yield ev


def ingest_evtx_path(db: Session, path: str, label: str | None = None) -> dict[str, Any]:
    p = Path(path)
    files = sorted(p.rglob("*.evtx")) if p.is_dir() else [p]
    if not files or not all(f.exists() for f in files):
        raise FileNotFoundError(f"No EVTX files found at {path}")
    total = {"files": 0, "added": 0, "skipped_duplicates": 0}
    for f in files:
        rel = label or (str(f.relative_to(p)) if p.is_dir() else f.name)
        res = _store(db, _iter_evtx(f, rel), "evtx")
        total["files"] += 1
        total["added"] += res["added"]
        total["skipped_duplicates"] += res["skipped_duplicates"]
    return total


def ingest_github_sample(db: Session, sample_path: str) -> dict[str, Any]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = CACHE_DIR / re.sub(r"[^A-Za-z0-9._-]+", "_", sample_path)
    if not dest.exists():
        url = EVTX_REPO_RAW + urllib.parse.quote(sample_path, safe="/")
        tmp = dest.with_suffix(".part")
        urllib.request.urlretrieve(url, tmp)
        tmp.replace(dest)
    res = _store(db, _iter_evtx(dest, sample_path), "evtx")
    return {"sample": sample_path, **res}


def ingest_jsonl(db: Session, path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    opener = gzip.open if p.suffix == ".gz" else open

    def gen():
        with opener(p, "rt", encoding="utf-8", errors="ignore") as fh:  # type: ignore[arg-type]
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = normalize_json_event(json.loads(line), p.name)
                except json.JSONDecodeError:
                    continue
                if ev:
                    yield ev

    return _store(db, gen(), "jsonl")


def ingest_default_samples(db: Session) -> dict[str, Any]:
    results, errors = [], []
    for s in DEFAULT_SAMPLES:
        try:
            results.append(ingest_github_sample(db, s))
        except Exception as exc:  # noqa: BLE001
            errors.append({"sample": s, "error": str(exc)})
    return {"ingested": results, "errors": errors}


# --------------------------------------------------------------------------
# Query / summary
# --------------------------------------------------------------------------
def event_count(db: Session) -> int:
    return db.query(func.count(TelemetryEvent.id)).scalar() or 0


def iter_events(db: Session, category: str | None, service: str | None, product: str | None = None) -> Iterator[tuple[TelemetryEvent, dict[str, Any]]]:
    q = db.query(TelemetryEvent)
    if product:
        q = q.filter(TelemetryEvent.product == product.lower())
    if category:
        q = q.filter(TelemetryEvent.category == category)
    if service:
        q = q.filter(TelemetryEvent.service == service)
    for row in q.yield_per(1000):
        try:
            yield row, json.loads(row.fields_json)
        except json.JSONDecodeError:
            continue


def available_fields(db: Session, category: str | None = None, service: str | None = None, sample: int = 400) -> set[str]:
    q = db.query(TelemetryEvent.fields_json)
    if category:
        q = q.filter(TelemetryEvent.category == category)
    if service:
        q = q.filter(TelemetryEvent.service == service)
    out: set[str] = set()
    for (blob,) in q.limit(sample).all():
        try:
            out |= set(json.loads(blob))
        except json.JSONDecodeError:
            pass
    return out


def summary(db: Session) -> dict[str, Any]:
    total = event_count(db)
    by_cat = Counter()
    for cat, n in db.query(TelemetryEvent.category, func.count(TelemetryEvent.id)).group_by(TelemetryEvent.category).all():
        by_cat[cat or "uncategorized"] = n
    sources = [
        {"source": s, "kind": k, "events": n}
        for s, k, n in db.query(TelemetryEvent.source, TelemetryEvent.source_kind, func.count(TelemetryEvent.id))
        .group_by(TelemetryEvent.source, TelemetryEvent.source_kind).order_by(func.count(TelemetryEvent.id).desc()).limit(50).all()
    ]
    hosts = [h for (h,) in db.query(TelemetryEvent.host).distinct().limit(25).all() if h]
    return {"total_events": total, "by_category": dict(by_cat), "sources": sources, "hosts": hosts}
