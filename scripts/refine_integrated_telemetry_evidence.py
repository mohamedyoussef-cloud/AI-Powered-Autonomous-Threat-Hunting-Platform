from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

ATTACK_TECHNIQUES = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

INTEGRATED_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "integrated"
)

INPUT = (
    INTEGRATED_DIR
    / "integrated_telemetry_evidence.csv"
)

ROW_OUTPUT = (
    INTEGRATED_DIR
    / "integrated_telemetry_evidence_v1_1.csv"
)

COMPONENT_OUTPUT = (
    INTEGRATED_DIR
    / "data_component_telemetry_evidence_summary_v1_1.csv"
)

TECHNIQUE_OUTPUT = (
    INTEGRATED_DIR
    / "technique_telemetry_evidence_summary_v1_1.csv"
)

SUMMARY_OUTPUT = (
    INTEGRATED_DIR
    / "integrated_telemetry_evidence_summary_v1_1.json"
)

VERSION = "1.1.0"


def read_jsonl(path: Path):
    rows = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))

    return rows


techniques = read_jsonl(ATTACK_TECHNIQUES)

if len(techniques) != 697:
    raise RuntimeError(
        f"Expected 697 active techniques, found {len(techniques)}"
    )


with INPUT.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    rows = list(csv.DictReader(f))


if len(rows) != 398098:
    raise RuntimeError(
        f"Expected 398098 evidence rows, found {len(rows)}"
    )


def bots_exact(row):
    return row["bots_evidence_status"] == "exact_source"


def bots_family(row):
    return row["bots_evidence_status"] not in {
        "none",
        "not_specified",
        "exact_source",
    }


def evtx_source_observed(row):
    return row["evtx_evidence_status"] in {
        "exact_event_id",
        "channel_observed",
        "no_exact_event_id",
    }


def classify_row(row):

    source = row["mitre_log_source"].strip()
    channel = row["mitre_channel"].strip()
    required_ids = row["required_event_ids"].strip()

    requirement_present = bool(source or channel)

    if not requirement_present:
        return "requirement_unspecified", 0

    # -------------------------------------------------
    # ATT&CK explicitly requires one or more Event IDs.
    #
    # Source existence alone must NOT be considered
    # exact satisfaction of that requirement.
    # -------------------------------------------------
    if required_ids:

        if row["evtx_evidence_status"] == "exact_event_id":
            return "exact_event_observed", 3

        if bots_exact(row) or evtx_source_observed(row):
            return "source_observed_event_unverified", 1

        if bots_family(row):
            return "source_family_observed_event_unverified", 1

        return "not_observed", 0

    # -------------------------------------------------
    # No explicit Event ID requirement.
    # Source/channel evidence can be used directly.
    # -------------------------------------------------
    if bots_exact(row) or evtx_source_observed(row):
        return "source_observed", 2

    if bots_family(row):
        return "source_family_observed", 1

    return "not_observed", 0


refined_rows = []


for row in rows:

    status, strength = classify_row(row)

    sources = []

    if row["bots_evidence_status"] not in {
        "none",
        "not_specified",
    }:
        sources.append("BOTS")

    if row["evtx_evidence_status"] in {
        "exact_event_id",
        "channel_observed",
        "no_exact_event_id",
    }:
        sources.append("EVTX")

    new_row = dict(row)

    # Keep legacy classification for lineage/audit.
    new_row["legacy_telemetry_evidence_status"] = (
        row["telemetry_evidence_status"]
    )

    new_row["telemetry_evidence_version"] = VERSION
    new_row["telemetry_evidence_status"] = status
    new_row["evidence_strength"] = strength
    new_row["evidence_sources"] = " | ".join(sorted(set(sources)))

    refined_rows.append(new_row)


row_fieldnames = list(refined_rows[0].keys())

with ROW_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=row_fieldnames,
    )

    writer.writeheader()
    writer.writerows(refined_rows)


# =========================================================
# Data-component-level aggregation
# =========================================================

STATUS_RANK = {
    "exact_event_observed": 6,
    "source_observed": 5,
    "source_family_observed": 4,
    "source_observed_event_unverified": 3,
    "source_family_observed_event_unverified": 2,
    "not_observed": 1,
    "requirement_unspecified": 0,
}


component_groups = defaultdict(list)


for row in refined_rows:

    component_id = row["data_component_id"]

    if not component_id:
        continue

    key = (
        row["technique_id"],
        component_id,
    )

    component_groups[key].append(row)


component_rows = []


for (technique_id, component_id), group in component_groups.items():

    best = max(
        group,
        key=lambda r: STATUS_RANK[
            r["telemetry_evidence_status"]
        ],
    )

    statuses = {
        r["telemetry_evidence_status"]
        for r in group
    }

    exact_event = (
        "exact_event_observed"
        in statuses
    )

    any_evidence = any(
        status not in {
            "not_observed",
            "requirement_unspecified",
        }
        for status in statuses
    )

    explicit_event_requirement = any(
        bool(r["required_event_ids"].strip())
        for r in group
    )

    sources = sorted({
        source
        for row in group
        for source in (
            row["evidence_sources"].split(" | ")
            if row["evidence_sources"]
            else []
        )
    })

    log_source_keys = {
        (
            r["mitre_log_source"],
            r["mitre_channel"],
        )
        for r in group
        if (
            r["mitre_log_source"]
            or r["mitre_channel"]
        )
    }

    component_rows.append(
        {
            "technique_id":
                technique_id,

            "technique_name":
                group[0]["technique_name"],

            "data_component_id":
                component_id,

            "data_component_name":
                group[0]["data_component_name"],

            "requirement_rows":
                len(group),

            "unique_log_source_requirements":
                len(log_source_keys),

            "has_explicit_event_id_requirement":
                explicit_event_requirement,

            "exact_event_evidence":
                exact_event,

            "any_source_evidence":
                any_evidence,

            "best_evidence_status":
                best["telemetry_evidence_status"],

            "best_evidence_strength":
                int(best["evidence_strength"]),

            "evidence_sources":
                " | ".join(sources),
        }
    )


component_rows.sort(
    key=lambda r: (
        r["technique_id"],
        r["data_component_id"],
    )
)


component_fields = [
    "technique_id",
    "technique_name",
    "data_component_id",
    "data_component_name",
    "requirement_rows",
    "unique_log_source_requirements",
    "has_explicit_event_id_requirement",
    "exact_event_evidence",
    "any_source_evidence",
    "best_evidence_status",
    "best_evidence_strength",
    "evidence_sources",
]


with COMPONENT_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=component_fields,
    )

    writer.writeheader()
    writer.writerows(component_rows)


# =========================================================
# Technique-level factual aggregation
#
# This is still NOT the Phase 3 weighted readiness score.
# =========================================================

components_by_technique = defaultdict(list)

for row in component_rows:
    components_by_technique[
        row["technique_id"]
    ].append(row)


technique_rows = []


for technique in techniques:

    tid = technique["technique_id"]

    components = components_by_technique.get(
        tid,
        [],
    )

    total_components = len(components)

    components_with_evidence = sum(
        1
        for row in components
        if row["any_source_evidence"]
    )

    exact_event_components = sum(
        1
        for row in components
        if row["exact_event_evidence"]
    )

    source_only_components = (
        components_with_evidence
        - exact_event_components
    )

    component_coverage = (
        (
            components_with_evidence
            / total_components
        )
        * 100.0
        if total_components
        else 0.0
    )

    exact_event_coverage = (
        (
            exact_event_components
            / total_components
        )
        * 100.0
        if total_components
        else 0.0
    )

    if total_components == 0:

        overall_status = (
            "requirement_unspecified"
        )

    elif components_with_evidence == 0:

        overall_status = (
            "not_observed"
        )

    elif components_with_evidence < total_components:

        overall_status = (
            "partial_component_evidence"
        )

    else:

        overall_status = (
            "full_component_evidence"
        )

    sources = sorted({
        source
        for row in components
        for source in (
            row["evidence_sources"].split(" | ")
            if row["evidence_sources"]
            else []
        )
    })

    technique_rows.append(
        {
            "technique_id":
                tid,

            "technique_name":
                technique["name"],

            "platforms":
                " | ".join(
                    technique.get(
                        "platforms",
                        [],
                    )
                ),

            "tactics":
                " | ".join(
                    technique.get(
                        "tactics",
                        [],
                    )
                ),

            "data_components_referenced":
                total_components,

            "data_components_with_any_evidence":
                components_with_evidence,

            "data_components_with_exact_event_evidence":
                exact_event_components,

            "data_components_source_only":
                source_only_components,

            "component_evidence_coverage_pct":
                round(
                    component_coverage,
                    6,
                ),

            "exact_event_component_coverage_pct":
                round(
                    exact_event_coverage,
                    6,
                ),

            "telemetry_evidence_status":
                overall_status,

            "evidence_sources":
                " | ".join(sources),
        }
    )


technique_fields = [
    "technique_id",
    "technique_name",
    "platforms",
    "tactics",
    "data_components_referenced",
    "data_components_with_any_evidence",
    "data_components_with_exact_event_evidence",
    "data_components_source_only",
    "component_evidence_coverage_pct",
    "exact_event_component_coverage_pct",
    "telemetry_evidence_status",
    "evidence_sources",
]


with TECHNIQUE_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=technique_fields,
    )

    writer.writeheader()
    writer.writerows(technique_rows)


# =========================================================
# Quality gates
# =========================================================

expected_component_refs = sum(
    len(
        technique.get(
            "data_components",
            [],
        )
        or []
    )
    for technique in techniques
)


allowed_row_statuses = set(
    STATUS_RANK
)


invalid_row_statuses = [
    row
    for row in refined_rows
    if row["telemetry_evidence_status"]
    not in allowed_row_statuses
]


# Exact-event classification must ONLY exist
# where EVTX exact Event-ID evidence exists.
false_exact_rows = [
    row
    for row in refined_rows
    if (
        row["telemetry_evidence_status"]
        == "exact_event_observed"
        and
        row["evtx_evidence_status"]
        != "exact_event_id"
    )
]


# Explicit event requirement must never be
# silently upgraded to ordinary source_observed.
event_requirement_overclaims = [
    row
    for row in refined_rows
    if (
        row["required_event_ids"].strip()
        and
        row["telemetry_evidence_status"]
        in {
            "source_observed",
            "source_family_observed",
        }
    )
]


row_status_counts = Counter(
    row["telemetry_evidence_status"]
    for row in refined_rows
)

technique_status_counts = Counter(
    row["telemetry_evidence_status"]
    for row in technique_rows
)


summary = {
    "artifact":
        "Integrated Telemetry Evidence",

    "artifact_version":
        VERSION,

    "active_techniques":
        len(techniques),

    "evidence_rows":
        len(refined_rows),

    "expected_technique_component_references":
        expected_component_refs,

    "component_summary_rows":
        len(component_rows),

    "technique_summary_rows":
        len(technique_rows),

    "exact_event_observed_rows":
        row_status_counts.get(
            "exact_event_observed",
            0,
        ),

    "event_requirement_unverified_rows":
        (
            row_status_counts.get(
                "source_observed_event_unverified",
                0,
            )
            +
            row_status_counts.get(
                "source_family_observed_event_unverified",
                0,
            )
        ),

    "false_exact_event_rows":
        len(false_exact_rows),

    "event_requirement_overclaim_rows":
        len(event_requirement_overclaims),

    "invalid_status_rows":
        len(invalid_row_statuses),

    "row_status_counts":
        dict(
            sorted(
                row_status_counts.items()
            )
        ),

    "technique_status_counts":
        dict(
            sorted(
                technique_status_counts.items()
            )
        ),

    "important_note": (
        "These fields describe observed telemetry evidence. "
        "They are not the Phase 3 weighted Telemetry Readiness score, "
        "and they do not prove that a technique itself occurs in a dataset."
    ),

    "status": (
        "PASS"
        if (
            len(techniques) == 697
            and
            len(refined_rows) == 398098
            and
            len(component_rows)
            == expected_component_refs
            and
            len(technique_rows) == 697
            and
            not false_exact_rows
            and
            not event_requirement_overclaims
            and
            not invalid_row_statuses
        )
        else "FAIL"
    ),
}


with SUMMARY_OUTPUT.open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        summary,
        f,
        indent=2,
    )


print(json.dumps(summary, indent=2))

print()
print(f"Evidence v1.1:   {ROW_OUTPUT}")
print(f"Components:      {COMPONENT_OUTPUT}")
print(f"Techniques:      {TECHNIQUE_OUTPUT}")
print(f"Summary:         {SUMMARY_OUTPUT}")
