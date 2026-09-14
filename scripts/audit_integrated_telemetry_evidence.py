from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]

ATTACK = (
    PROJECT
    / "data"
    / "processed"
    / "knowledge"
)

INTEGRATED = (
    PROJECT
    / "data"
    / "processed"
    / "telemetry"
    / "integrated"
)

TECHNIQUES = ATTACK / "attack_techniques_active.jsonl"
COMPONENTS = ATTACK / "attack_data_components.jsonl"

EVIDENCE = (
    INTEGRATED
    / "integrated_telemetry_evidence.csv"
)


def read_jsonl(path):
    with path.open("r", encoding="utf-8") as f:
        return [
            json.loads(line)
            for line in f
            if line.strip()
        ]


techniques = read_jsonl(TECHNIQUES)
components = read_jsonl(COMPONENTS)

component_by_id = {
    row["external_id"]: row
    for row in components
}

with EVIDENCE.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    evidence = list(csv.DictReader(f))


# -----------------------------------------
# ATT&CK expansion audit
# -----------------------------------------

component_refs = 0
expected_rows = 0

for technique in techniques:

    component_ids = (
        technique.get("data_components")
        or []
    )

    if not component_ids:
        expected_rows += 1
        continue

    component_refs += len(component_ids)

    for cid in component_ids:

        component = component_by_id[cid]

        log_sources = (
            component
            .get("raw", {})
            .get("x_mitre_log_sources", [])
            or []
        )

        expected_rows += max(
            1,
            len(log_sources),
        )


component_source_counts = []

for component in components:

    sources = (
        component
        .get("raw", {})
        .get("x_mitre_log_sources", [])
        or []
    )

    component_source_counts.append(
        {
            "component_id":
                component["external_id"],
            "component_name":
                component["name"],
            "log_source_count":
                len(sources),
        }
    )


component_source_counts.sort(
    key=lambda r: r["log_source_count"],
    reverse=True,
)


# -----------------------------------------
# Evidence semantic audit
# -----------------------------------------

required_event_rows = [
    r for r in evidence
    if r["required_event_ids"].strip()
]

exact_evtx_rows = [
    r for r in evidence
    if r["evtx_evidence_status"]
    == "exact_event_id"
]

channel_evtx_rows = [
    r for r in evidence
    if r["evtx_evidence_status"]
    == "channel_observed"
]

bots_exact_rows = [
    r for r in evidence
    if r["bots_evidence_status"]
    == "exact_source"
]


# Critical:
# ATT&CK specifies Event ID(s), but current
# classification says available without an
# exact EVTX Event-ID match.
overclaimed_rows = [
    r for r in evidence
    if (
        r["required_event_ids"].strip()
        and
        r["telemetry_evidence_status"]
        == "available"
        and
        r["evtx_evidence_status"]
        != "exact_event_id"
    )
]


by_technique = defaultdict(list)

for row in evidence:
    by_technique[row["technique_id"]].append(row)


techniques_with_exact_evtx = set()

techniques_with_any_source_evidence = set()

current_available = set()

available_without_exact_evtx = set()


for tid, rows in by_technique.items():

    if any(
        r["evtx_evidence_status"]
        == "exact_event_id"
        for r in rows
    ):
        techniques_with_exact_evtx.add(tid)

    if any(
        r["bots_evidence_status"] != "none"
        or
        r["evtx_evidence_status"]
        in {
            "exact_event_id",
            "channel_observed",
        }
        for r in rows
    ):
        techniques_with_any_source_evidence.add(tid)

    if any(
        r["telemetry_evidence_status"]
        == "available"
        for r in rows
    ):
        current_available.add(tid)

        if not any(
            r["evtx_evidence_status"]
            == "exact_event_id"
            for r in rows
        ):
            available_without_exact_evtx.add(tid)


bots_status_counts = Counter(
    r["bots_evidence_status"]
    for r in evidence
)

evtx_status_counts = Counter(
    r["evtx_evidence_status"]
    for r in evidence
)

telemetry_status_counts = Counter(
    r["telemetry_evidence_status"]
    for r in evidence
)


summary = {
    "active_techniques": len(techniques),
    "data_components": len(components),
    "technique_component_references": component_refs,

    "expected_expanded_evidence_rows":
        expected_rows,

    "actual_evidence_rows":
        len(evidence),

    "expansion_matches":
        expected_rows == len(evidence),

    "total_component_log_source_entries":
        sum(
            r["log_source_count"]
            for r in component_source_counts
        ),

    "max_log_sources_on_single_component":
        max(
            r["log_source_count"]
            for r in component_source_counts
        ),

    "required_event_id_rows":
        len(required_event_rows),

    "exact_evtx_event_id_rows":
        len(exact_evtx_rows),

    "evtx_channel_only_rows":
        len(channel_evtx_rows),

    "bots_exact_source_rows":
        len(bots_exact_rows),

    "potentially_overclaimed_available_rows":
        len(overclaimed_rows),

    "current_available_techniques":
        len(current_available),

    "techniques_with_exact_evtx_event_evidence":
        len(techniques_with_exact_evtx),

    "techniques_with_any_source_evidence":
        len(techniques_with_any_source_evidence),

    "available_techniques_without_exact_evtx":
        len(available_without_exact_evtx),

    "bots_status_counts":
        dict(bots_status_counts),

    "evtx_status_counts":
        dict(evtx_status_counts),

    "row_telemetry_status_counts":
        dict(telemetry_status_counts),
}


print("=== INTEGRATED TELEMETRY AUDIT ===")
print(json.dumps(summary, indent=2))

print()
print("=== TOP 15 DATA COMPONENTS BY LOG-SOURCE COUNT ===")

for row in component_source_counts[:15]:
    print(
        f'{row["component_id"]:8} '
        f'{row["log_source_count"]:6}  '
        f'{row["component_name"]}'
    )
