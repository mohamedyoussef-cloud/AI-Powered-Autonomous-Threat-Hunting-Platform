from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(
    prefix="/admin-control",
    tags=["admin-control"]
)

STORE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "admin_controls.json"
)

DEFAULTS = {
    "maintenance_mode": False,
    "audit_logging": True,
    "auto_refresh": True,
    "campaign_execution": True,
    "detection_generation": True,
    "require_detection_validation": True,
    "allow_source_changes": True,
    "finding_retention_days": 180,
    "session_timeout_minutes": 60,
}


def _read() -> dict[str, Any]:
    STORE.parent.mkdir(parents=True, exist_ok=True)

    if not STORE.exists():
        return {
            "settings": DEFAULTS.copy(),
            "audit": []
        }

    try:
        data=json.loads(
            STORE.read_text(encoding="utf-8")
        )

        return {
            "settings":{
                **DEFAULTS,
                **data.get("settings", {})
            },
            "audit":data.get("audit", [])
        }

    except Exception:
        return {
            "settings":DEFAULTS.copy(),
            "audit":[]
        }


def _write(data:dict[str,Any]):
    STORE.parent.mkdir(parents=True,exist_ok=True)

    STORE.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )


def _record(
    data:dict[str,Any],
    actor:str,
    action:str,
    obj:str
):
    if not data["settings"].get(
        "audit_logging",
        True
    ):
        return

    data.setdefault("audit",[]).insert(
        0,
        {
            "actor":actor or "Administrator",
            "action":action,
            "object":obj,
            "time":datetime.now(
                timezone.utc
            ).astimezone().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }
    )

    data["audit"]=data["audit"][:100]


@router.get("")
def get_controls():
    data=_read()

    return {
        "settings":data["settings"],
        "audit":data["audit"]
    }


@router.patch("")
def update_controls(
    payload:dict[str,Any]
):
    data=_read()

    actor=str(
        payload.get(
            "actor",
            "Administrator"
        )
    )

    settings=payload.get(
        "settings",
        {}
    )

    if not isinstance(settings,dict):
        raise HTTPException(
            400,
            "settings must be an object"
        )

    changed=[]

    for key,value in settings.items():

        if key not in DEFAULTS:
            raise HTTPException(
                400,
                f"Unknown administrator control: {key}"
            )

        if key in {
            "finding_retention_days",
            "session_timeout_minutes"
        }:
            try:
                value=int(value)
            except Exception:
                raise HTTPException(
                    400,
                    f"{key} must be numeric"
                )

            if value<=0:
                raise HTTPException(
                    400,
                    f"{key} must be greater than zero"
                )

        elif not isinstance(value,bool):
            raise HTTPException(
                400,
                f"{key} must be boolean"
            )

        data["settings"][key]=value
        changed.append(
            f"{key}={value}"
        )

    if changed:
        _record(
            data,
            actor,
            "Updated workspace controls",
            ", ".join(changed)
        )

    _write(data)

    return {
        "settings":data["settings"],
        "audit":data["audit"]
    }


@router.put("")
def reset_controls(
    payload:dict[str,Any]
):
    data=_read()

    actor=str(
        payload.get(
            "actor",
            "Administrator"
        )
    )

    data["settings"]=DEFAULTS.copy()

    _record(
        data,
        actor,
        "Restored safe defaults",
        "Workspace controls"
    )

    _write(data)

    return {
        "settings":data["settings"],
        "audit":data["audit"]
    }
