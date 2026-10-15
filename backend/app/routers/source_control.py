"""
Workspace-level data source control.

Pipeline-backed sources remain traceable to the original pipeline registry.
Workspace-managed sources can be added, edited, enabled/disabled and removed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from app.services.dataset_catalog import load_catalog

router = APIRouter(
    prefix="/source-control",
    tags=["source-control"]
)

STORE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "managed_sources.json"
)


def _read() -> dict[str, Any]:
    STORE.parent.mkdir(parents=True, exist_ok=True)

    if not STORE.exists():
        return {
            "custom": [],
            "overrides": {}
        }

    try:
        return json.loads(
            STORE.read_text(encoding="utf-8")
        )
    except Exception:
        return {
            "custom": [],
            "overrides": {}
        }


def _write(data: dict[str, Any]) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)

    STORE.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def _combined() -> list[dict[str, Any]]:
    data = _read()
    overrides = data.get("overrides", {})

    result = []

    for src in load_catalog():

        item = {
            **src,
            "managed": False,
            "enabled": True,
            "source_type": src.get(
                "format_spec",
                "Pipeline source"
            ),
            "description": src.get(
                "intended_platform_use",
                ""
            ),
        }

        item.update(
            overrides.get(
                src["source_id"],
                {}
            )
        )

        result.append(item)

    for src in data.get("custom", []):
        result.append({
            "managed": True,
            "enabled": True,
            **src
        })

    return result


@router.get("")
def list_sources():
    return {
        "items": _combined()
    }


@router.post("")
def add_source(payload: dict[str, Any]):

    data = _read()

    name = str(
        payload.get("name", "")
    ).strip()

    if not name:
        raise HTTPException(
            400,
            "Source name is required"
        )

    source_id = str(
        payload.get("source_id")
        or name.lower().replace(" ", "_")
    ).strip()

    source_id = "".join(
        ch
        if ch.isalnum() or ch in "_-"
        else "_"
        for ch in source_id
    )

    if any(
        x.get("source_id") == source_id
        for x in _combined()
    ):
        raise HTTPException(
            409,
            f"Source ID '{source_id}' already exists"
        )

    now = datetime.now(
        timezone.utc
    ).isoformat()

    item = {
        "source_id": source_id,
        "name": name,
        "source_type": str(
            payload.get(
                "source_type",
                "Custom"
            )
        ),
        "endpoint": str(
            payload.get(
                "endpoint",
                ""
            )
        ),
        "description": str(
            payload.get(
                "description",
                ""
            )
        ),
        "enabled": bool(
            payload.get(
                "enabled",
                True
            )
        ),
        "raw_status": "workspace_defined",
        "health_status": "configuration pending",
        "record_count": None,
        "file_count": 0,
        "created_at": now,
        "updated_at": now,
    }

    data.setdefault(
        "custom",
        []
    ).append(item)

    _write(data)

    return item


@router.patch("/{source_id}")
def update_source(
    source_id: str,
    payload: dict[str, Any]
):

    data = _read()

    now = datetime.now(
        timezone.utc
    ).isoformat()

    for item in data.setdefault(
        "custom",
        []
    ):

        if item.get(
            "source_id"
        ) == source_id:

            for key in (
                "name",
                "source_type",
                "endpoint",
                "description",
                "enabled"
            ):
                if key in payload:
                    item[key] = payload[key]

            item["updated_at"] = now

            _write(data)

            return item

    catalog_ids = {
        x["source_id"]
        for x in load_catalog()
    }

    if source_id not in catalog_ids:
        raise HTTPException(
            404,
            "Source not found"
        )

    override = (
        data.setdefault(
            "overrides",
            {}
        ).setdefault(
            source_id,
            {}
        )
    )

    for key in (
        "name",
        "source_type",
        "endpoint",
        "description",
        "enabled"
    ):
        if key in payload:
            override[key] = payload[key]

    override["updated_at"] = now

    _write(data)

    return next(
        x
        for x in _combined()
        if x["source_id"] == source_id
    )


@router.delete("/{source_id}")
def delete_source(source_id: str):

    data = _read()

    custom = data.setdefault(
        "custom",
        []
    )

    before = len(custom)

    data["custom"] = [
        x
        for x in custom
        if x.get("source_id") != source_id
    ]

    if len(data["custom"]) == before:
        raise HTTPException(
            400,
            "Pipeline-backed sources cannot be removed; disable or edit their workspace override instead."
        )

    _write(data)

    return {
        "ok": True,
        "source_id": source_id
    }
