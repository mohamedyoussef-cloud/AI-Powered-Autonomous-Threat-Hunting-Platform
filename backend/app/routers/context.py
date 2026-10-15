"""
Hunting context inputs: historical incidents, assets, network topology,
users and organisation context. Workspace-managed JSON store (same pattern
as source_control). Read: any signed-in user. Write: analyst or admin.
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from app.core.security import require_analyst, require_user

router = APIRouter(prefix="/context", tags=["context"])

STORE = Path(__file__).resolve().parents[1] / "data" / "context_inputs.json"
_LOCK = threading.Lock()

FIELDS: dict[str, list[str]] = {
    "incidents": ["title", "techniques", "severity", "occurred", "assets"],
    "assets": ["name", "type", "os", "criticality", "owner"],
    "topology": ["segment", "cidr", "zone", "notes"],
    "users": ["user", "role", "department", "privileged"],
    "organization": ["key", "value"],
}
MAX_ITEMS = 5000


def _load() -> dict[str, list[dict[str, Any]]]:
    try:
        data = json.loads(STORE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    return {k: list(data.get(k, [])) for k in FIELDS}


def _save(data: dict[str, list[dict[str, Any]]]) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(STORE)


def _kind(kind: str) -> str:
    if kind not in FIELDS:
        raise HTTPException(404, f"Unknown context kind '{kind}'. Use one of: {', '.join(FIELDS)}")
    return kind


def _clean(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    row = {f: str(raw.get(f, "")).strip()[:500] for f in FIELDS[kind]}
    if not any(row.values()):
        raise HTTPException(422, "Empty record.")
    row["id"] = uuid.uuid4().hex[:10]
    row["created_at"] = datetime.now(timezone.utc).isoformat()
    return row


@router.get("")
def summary(_=Depends(require_user)):
    data = _load()
    return {"counts": {k: len(v) for k, v in data.items()}, "fields": FIELDS}


@router.get("/{kind}")
def list_items(kind: str, _=Depends(require_user)):
    items = _load()[_kind(kind)]
    return {"kind": kind, "fields": FIELDS[kind], "total": len(items), "items": items}


@router.post("/{kind}")
def add_items(kind: str, payload: Any = Body(...), _=Depends(require_analyst)):
    """Accepts one record (object) or a bulk list of records."""
    _kind(kind)
    rows = payload if isinstance(payload, list) else [payload]
    if not rows or not all(isinstance(r, dict) for r in rows):
        raise HTTPException(422, "Send an object or a list of objects.")
    with _LOCK:
        data = _load()
        if len(data[kind]) + len(rows) > MAX_ITEMS:
            raise HTTPException(413, f"Limit of {MAX_ITEMS} records per kind.")
        new = [_clean(kind, r) for r in rows]
        data[kind].extend(new)
        _save(data)
    return {"added": len(new), "total": len(data[kind])}


@router.delete("/{kind}/{item_id}")
def delete_item(kind: str, item_id: str, _=Depends(require_analyst)):
    _kind(kind)
    with _LOCK:
        data = _load()
        before = len(data[kind])
        data[kind] = [x for x in data[kind] if x.get("id") != item_id]
        if len(data[kind]) == before:
            raise HTTPException(404, "Record not found.")
        _save(data)
    return {"deleted": item_id}
