
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter

from app.core.config import get_settings


router = APIRouter(
    prefix="/integration",
    tags=["project-integration"],
)

settings = get_settings()


def load_json(path: Path):
    if not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return None


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0

    count = 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:
        for line in f:
            if line.strip():
                count += 1

    return count


@router.get("/status")
def integration_status():

    root = Path(
        settings.PIPELINE_DATA_ROOT
    )

    canonical = root / "canonical"

    phase3 = root / "processed" / "phase3"

    # --------------------------------------------------------
    # ATT&CK
    # --------------------------------------------------------

    attack_report = load_json(
        canonical / "attack_parse_report.json"
    )

    attack_count = None

    if attack_report:
        summary = attack_report.get(
            "summary",
            {}
        )

        attack_count = (
            summary.get("technique_count")
            or summary.get("techniques")
        )

    # --------------------------------------------------------
    # SIGMA
    # --------------------------------------------------------

    sigma_report = load_json(
        canonical / "sigma_parse_report.json"
    )

    sigma_total = None
    sigma_accepted = None

    if sigma_report:

        sigma_total = sigma_report.get(
            "total_files"
        )

        categories = sigma_report.get(
            "quarantine_category_counts",
            {}
        )

        sigma_accepted = categories.get(
            "accepted_core"
        )

    # --------------------------------------------------------
    # EVTX
    # --------------------------------------------------------

    evtx_report = load_json(
        canonical / "evtx_parse_report.json"
    )

    evtx_files = None
    evtx_events = None

    if evtx_report:
        evtx_files = evtx_report.get(
            "total_files"
        )
        evtx_events = evtx_report.get(
            "total_events_parsed"
        )

    # --------------------------------------------------------
    # HYPOTHESIS ENGINE
    # --------------------------------------------------------

    hypothesis_candidates = [
        phase3 / "hypothesis_engine" /
        "runtime_hunt_outputs_v1.jsonl",

        phase3 / "hypothesis_engine" /
        "hypothesis_outputs_v1.jsonl",

        phase3 / "hypothesis_engine" /
        "hypotheses.jsonl",
    ]

    hypothesis_file = next(
        (
            x
            for x in hypothesis_candidates
            if x.exists()
        ),
        None,
    )

    hypothesis_count = (
        count_jsonl(hypothesis_file)
        if hypothesis_file
        else None
    )

    # --------------------------------------------------------
    # Detection / Sigma generated artifacts
    # --------------------------------------------------------

    generated_candidates = [
        phase3 / "sigma" /
        "generated_sigma_rules.jsonl",

        phase3 / "sigma_generation" /
        "generated_sigma_rules.jsonl",

        root / "processed" /
        "sigma_generation" /
        "generated_sigma_rules.jsonl",
    ]

    generated_file = next(
        (
            x
            for x in generated_candidates
            if x.exists()
        ),
        None,
    )

    generated_sigma_count = (
        count_jsonl(generated_file)
        if generated_file
        else None
    )

    # --------------------------------------------------------
    # Status is based on actual files, not hard-coded claims.
    # --------------------------------------------------------

    return {
        "pipeline_root": str(root),

        "stages": {
            "attack": {
                "available": attack_count is not None,
                "techniques": attack_count,
            },

            "sigma": {
                "available": sigma_report is not None,
                "total_files": sigma_total,
                "accepted_core": sigma_accepted,
            },

            "evtx": {
                "available": evtx_report is not None,
                "files": evtx_files,
                "events": evtx_events,
            },

            "hypothesis_engine": {
                "available": hypothesis_file is not None,
                "records": hypothesis_count,
                "file": (
                    str(hypothesis_file)
                    if hypothesis_file
                    else None
                ),
            },

            "generated_sigma": {
                "available": generated_file is not None,
                "records": generated_sigma_count,
                "file": (
                    str(generated_file)
                    if generated_file
                    else None
                ),
            },

            "fine_tuning": {
                "available": False,
                "status": "not integrated yet",
            },
        }
    }
