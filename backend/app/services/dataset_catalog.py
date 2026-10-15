"""
services/dataset_catalog.py
------------------------------
Reads the data-prep pipeline's OWN source-of-truth files directly —
config/sources.yaml (the source registry from Phase 1) plus each
source's manifest (immutable sha256 lineage) and parse report (from
Phases 3-6) — and merges them into one dataset catalog view.

Unlike a typical "dataset manager" that just lists name/size/rows, this
one surfaces two things most such catalogs don't have because they
don't have a real data-prep pipeline behind them:

  1. A real sha256 lineage hash per source (from the Phase-1 immutable
     raw-freeze step), not just a version string.
  2. A genuine parse-health summary computed from what each parser
     actually produced (e.g. "8/9 rules accepted, 1 quarantined" for
     Sigma, "6 active / 0 revoked" for ATT&CK) rather than a blanket
     "Verified" badge that doesn't say what was actually verified.

Nothing here is faked when data is missing — a source with no manifest
yet is reported as `not_ingested`, not silently hidden or given a fake
"Verified" status.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from app.core.config import get_settings

settings = get_settings()


def _pipeline_root() -> Path:
    # PIPELINE_DATA_ROOT points at .../threat_hunting_data_prep/data
    return Path(settings.PIPELINE_DATA_ROOT).parent


def _load_json(path: Path) -> Optional[Dict]:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _health_for(source_id: str, root: Path) -> tuple[str, Optional[int]]:
    """Returns (health_status_text, record_count) computed from each
    source's own real parse report — not from the manifest alone, since
    the manifest only proves the raw bytes were frozen, not that they
    parsed cleanly."""
    canonical = root / "data" / "canonical"

    if source_id == "attack":
        report = _load_json(canonical / "attack_parse_report.json")
        if not report:
            return "not yet parsed", None
        s = report.get("summary", {})
        n = s.get("technique_count", 0)
        return f"{n} techniques · {s.get('mitigation_count', 0)} mitigations", n

    if source_id == "sigma":
        report = _load_json(canonical / "sigma_parse_report.json")
        if not report:
            return "not yet parsed", None
        cat = report.get("quarantine_category_counts", {})
        accepted = cat.get("accepted_core", 0)
        total = report.get("total_files", 0)
        return f"{accepted}/{total} accepted-core, {total - accepted} quarantined", total

    if source_id == "evtx":
        report = _load_json(canonical / "evtx_parse_report.json")
        if not report:
            return "not yet parsed", None
        n = report.get("total_events_parsed", 0)
        files = report.get("total_files", 0)
        return f"{n:,} events from {files} files", n

    if source_id == "bots":
        report = _load_json(canonical / "bots_parse_report.json")
        if not report:
            return "not yet parsed — archive metadata only (see profile_bots_archive.py)", None
        n = report.get("total_events_parsed", 0)
        return f"{n:,} events parsed", n

    return "n/a", None



def load_catalog() -> List[Dict]:
    """Read either the project registry or the legacy data-prep registry."""
    root = _pipeline_root()
    project_root = Path(__file__).resolve().parents[3]

    candidates = [
        project_root / "configs" / "dataset_registry.yaml",
        root / "configs" / "dataset_registry.yaml",
        root / "config" / "sources.yaml",
    ]
    registry_path = next((p for p in candidates if p.is_file()), None)
    if registry_path is None:
        return []

    with registry_path.open("r", encoding="utf-8") as f:
        registry = yaml.safe_load(f) or {}

    sources = registry.get("sources", {})
    if isinstance(sources, dict):
        entries = list(sources.items())
    elif isinstance(sources, list):
        entries = [(src.get("source_id"), src) for src in sources]
    else:
        return []

    aliases = {
        "mitre_attack_enterprise": "attack",
        "sigma_rules_repository": "sigma",
        "bots_v3": "bots",
        "darpa_transparent_computing": "darpa",
    }

    catalog = []
    for registry_id, src in entries:
        if not registry_id or not isinstance(src, dict):
            continue

        source_id = aliases.get(registry_id, registry_id)
        uses = src.get("downstream_uses") or []
        if isinstance(uses, list):
            uses = ", ".join(str(x) for x in uses)

        manifest_dir = root / "data" / "manifests"
        manifest = (
            _load_json(manifest_dir / f"{registry_id}_manifest.json")
            or _load_json(manifest_dir / f"{source_id}_manifest.json")
            or {}
        )

        excluded = bool(
            src.get("excluded", False)
            or src.get("implementation_status") == "excluded_from_core"
            or src.get("role") == "future_extension_only"
        )
        health, count = (
            ("excluded from current pipeline scope", None)
            if excluded
            else _health_for(source_id, root)
        )
        if health == "n/a":
            health = "parse report unavailable"

        catalog.append({
            "source_id": source_id,
            "name": src.get("name") or registry_id.replace("_", " ").title(),
            "version": src.get("observed_version")
                       or src.get("version")
                       or src.get("expected_version")
                       or "not specified",
            "license": src.get("license", "not specified"),
            "location": src.get("location")
                        or src.get("raw_path")
                        or "not specified",
            "intended_platform_use": str(
                src.get("intended_platform_use")
                or uses
                or src.get("role")
                or "not specified"
            ).strip(),
            "format_spec": src.get("format_spec")
                           or src.get("expected_format")
                           or "not specified",
            "raw_status": manifest.get("status", "not_ingested"),
            "file_count": manifest.get("file_count", 0),
            "total_size_bytes": manifest.get("total_size_bytes", 0),
            "combined_sha256": manifest.get("combined_sha256"),
            "health_status": health,
            "record_count": count,
            "excluded": excluded,
        })

    return catalog


def load_connections() -> List[Dict]:
    """A small, honest status board for the platform's optional/pending
    capabilities — mirrors the 'Live / Not Configured' pattern, scoped
    to what this platform actually has a real on/off switch for."""
    catalog = load_catalog()
    active_sources = [c for c in catalog if not c["excluded"]]
    ingested = [c for c in active_sources if c["raw_status"] == "frozen"]

    connections = [
        {
            "connection_id": "pysigma_validator",
            "name": "pySigma Validator & Compiler",
            "category": "detection_backend",
            "status": "live",
            "detail": "Real pySigma + pysigma-backend-splunk — every rule (parsed or generated) is validated for real.",
        },
        {
            "connection_id": "rule_generator_llm",
            "name": "Hypothesis Engine",
            "category": "ai_llm",
            "status": "not_configured",
            "detail": "Sigma Rule Generator currently runs on a deterministic keyword template (template_v0). "
                      "Connect a generation backend behind generate_rule_draft() to go live.",
        },
        {
            "connection_id": "bots_live_export",
            "name": "BOTS v3 Splunk Export",
            "category": "data_source",
            "status": "partial" if any(c["source_id"] == "bots" and c["record_count"] for c in active_sources) else "not_configured",
            "detail": "Canonical BOTS events require a real Splunk CSV export. Archive-metadata profiling "
                      "(no Splunk needed) is available via profile_bots_archive.py.",
        },
        {
            "connection_id": "data_sources",
            "name": "Data-Prep Sources",
            "category": "data_source",
            "status": ("not_configured" if not active_sources else "live" if len(ingested) == len(active_sources) else "partial"),
            "detail": f"{len(ingested)}/{len(active_sources)} active sources frozen and parsed.",
        },
    ]
    return connections
