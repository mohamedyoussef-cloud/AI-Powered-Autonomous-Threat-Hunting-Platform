from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

SCRIPT_PATH = Path(__file__).resolve()

PROJECT_ROOT = SCRIPT_PATH.parents[1]
WORKSPACE_ROOT = SCRIPT_PATH.parents[2]

ATTACK_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
)

EVTX_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
)

BOTS_DIR = (
    WORKSPACE_ROOT
    / "datasets"
    / "processed"
    / "botsv3"
)

TECHNIQUES_PATH = (
    ATTACK_DIR
    / "attack_techniques_active.jsonl"
)

COMPONENTS_PATH = (
    ATTACK_DIR
    / "attack_data_components.jsonl"
)

EVTX_PROFILE_PATH = (
    EVTX_DIR
    / "evtx_event_id_profile.csv"
)

EVTX_SUMMARY_PATH = (
    EVTX_DIR
    / "evtx_summary.json"
)

BOTS_INVENTORY_PATH = (
    BOTS_DIR
    / "profiling"
    / "sourcetype_search_inventory.csv"
)

BOTS_CAPABILITY_PATH = (
    BOTS_DIR
    / "telemetry"
    / "botsv3_telemetry_capability_matrix.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "integrated"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

EVIDENCE_OUTPUT = (
    OUTPUT_DIR
    / "integrated_telemetry_evidence.csv"
)

TECHNIQUE_OUTPUT = (
    OUTPUT_DIR
    / "technique_telemetry_evidence_summary.csv"
)

SUMMARY_OUTPUT = (
    OUTPUT_DIR
    / "integrated_telemetry_evidence_summary.json"
)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def read_jsonl(path: Path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            if line.strip():
                rows.append(
                    json.loads(line)
                )

    return rows


def norm(value: str | None) -> str:

    if not value:
        return ""

    return re.sub(
        r"[^a-z0-9]+",
        "",
        value.lower(),
    )


def extract_event_ids(
    channel_text: str | None,
):

    if not channel_text:
        return []

    text = channel_text.strip()

    if not re.search(
        r"(?i)\b(event\s*code|event\s*id|eventid)\b",
        text,
    ):
        return []

    values = re.findall(
        r"\b\d{1,5}\b",
        text,
    )

    return sorted(
        set(values),
        key=lambda x: int(x),
    )


def infer_capability(
    component_name: str,
    component_description: str,
):

    text = (
        f"{component_name} "
        f"{component_description}"
    ).lower()

    rules = [
        (
            "dns",
            (
                "dns",
                "domain name",
            ),
        ),
        (
            "authentication",
            (
                "authentication",
                "credential",
                "kerberos",
                "logon",
                "login",
                "ntlm",
            ),
        ),
        (
            "process",
            (
                "process",
                "command line",
                "powershell",
                "script execution",
            ),
        ),
        (
            "network_connection",
            (
                "network",
                "connection",
                "socket",
                "packet",
                "traffic",
                "flow",
            ),
        ),
        (
            "file",
            (
                "file",
                "directory",
            ),
        ),
        (
            "service",
            (
                "service",
                "daemon",
            ),
        ),
        (
            "database",
            (
                "database",
                "sql",
            ),
        ),
        (
            "web",
            (
                "http",
                "web",
            ),
        ),
        (
            "cloud",
            (
                "cloud",
                "aws",
                "azure",
                "gcp",
            ),
        ),
        (
            "identity",
            (
                "account",
                "identity",
                "user",
            ),
        ),
        (
            "host_context",
            (
                "host",
                "system",
                "computer",
            ),
        ),
    ]

    for capability, keywords in rules:

        if any(
            keyword in text
            for keyword in keywords
        ):
            return capability

    return ""


# ---------------------------------------------------------
# Load ATT&CK
# ---------------------------------------------------------

techniques = read_jsonl(
    TECHNIQUES_PATH
)

components = read_jsonl(
    COMPONENTS_PATH
)

if len(techniques) != 697:
    raise RuntimeError(
        "Expected 697 active ATT&CK techniques, "
        f"found {len(techniques)}"
    )


component_by_id = {
    row["external_id"]: row
    for row in components
}


# ---------------------------------------------------------
# Load EVTX
# ---------------------------------------------------------

with EVTX_PROFILE_PATH.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:

    evtx_profile = list(
        csv.DictReader(f)
    )


with EVTX_SUMMARY_PATH.open(
    "r",
    encoding="utf-8",
) as f:

    evtx_summary = json.load(f)


# ---------------------------------------------------------
# Load BOTS
# ---------------------------------------------------------

with BOTS_INVENTORY_PATH.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:

    bots_inventory = list(
        csv.DictReader(f)
    )


with BOTS_CAPABILITY_PATH.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:

    bots_capabilities = list(
        csv.DictReader(f)
    )


if len(bots_inventory) != 107:
    raise RuntimeError(
        "Expected 107 BOTS sourcetypes, "
        f"found {len(bots_inventory)}"
    )


bots_sourcetypes = [
    row["sourcetype"]
    for row in bots_inventory
]


bots_capability_lookup = {}

for row in bots_capabilities:

    key = (
        row["sourcetype"],
        row["capability"],
    )

    bots_capability_lookup[key] = row


# ---------------------------------------------------------
# BOTS source matching
# ---------------------------------------------------------

def bots_source_matches(
    mitre_source: str,
):

    if not mitre_source:
        return [], "none"

    source_norm = norm(
        mitre_source
    )

    # 1. Exact sourcetype normalization
    exact = [
        st
        for st in bots_sourcetypes
        if norm(st) == source_norm
    ]

    if exact:
        return exact, "exact_source"

    lower = mitre_source.lower()

    # 2. Linux-style ATT&CK aliases:
    # linux:syslog -> syslog
    if ":" in mitre_source:

        tail = mitre_source.split(
            ":",
            1,
        )[1]

        tail_exact = [
            st
            for st in bots_sourcetypes
            if norm(st) == norm(tail)
        ]

        if tail_exact:
            return (
                tail_exact,
                "source_alias",
            )

    # 3. Windows Event Log family
    if (
        "wineventlog" in source_norm
        or "xmlwineventlog" in source_norm
    ):

        tail = mitre_source.split(
            ":",
            1,
        )[-1]

        matches = [
            st
            for st in bots_sourcetypes
            if (
                "wineventlog"
                in norm(st)
                and (
                    norm(tail)
                    in norm(st)
                    or norm(st)
                    in norm(tail)
                )
            )
        ]

        if matches:
            return (
                matches,
                "windows_event_family",
            )

    # 4. Sysmon family
    if "sysmon" in lower:

        matches = [
            st
            for st in bots_sourcetypes
            if "sysmon" in st.lower()
        ]

        if matches:
            return (
                matches,
                "sysmon_family",
            )

    # 5. osquery family
    if "osquery" in lower:

        matches = [
            st
            for st in bots_sourcetypes
            if "osquery" in st.lower()
        ]

        if matches:
            return (
                matches,
                "osquery_family",
            )

    # 6. Generic network traffic
    if (
        "network traffic" in lower
        or lower.strip()
        == "network traffic"
    ):

        matches = [
            st
            for st in bots_sourcetypes
            if st.lower().startswith(
                "stream:"
            )
        ]

        if matches:
            return (
                matches,
                "network_stream_family",
            )

    return [], "none"


# ---------------------------------------------------------
# EVTX source matching
# ---------------------------------------------------------

def expected_evtx_channel(
    mitre_source: str,
):

    if not mitre_source:
        return ""

    source_norm = norm(
        mitre_source
    )

    if (
        "wineventlog" in source_norm
        or "xmlwineventlog" in source_norm
    ):

        if ":" in mitre_source:

            return mitre_source.split(
                ":",
                1,
            )[1]

    if "sysmon" in mitre_source.lower():
        return (
            "Microsoft-Windows-Sysmon/"
            "Operational"
        )

    return ""


def evtx_match(
    mitre_source: str,
    required_event_ids: list[str],
):

    expected_channel = (
        expected_evtx_channel(
            mitre_source
        )
    )

    channel_matches = []

    if expected_channel:

        ec = norm(
            expected_channel
        )

        channel_matches = [
            row
            for row in evtx_profile
            if (
                norm(
                    row["channel"]
                ) == ec
                or ec in norm(
                    row["channel"]
                )
                or norm(
                    row["channel"]
                ) in ec
            )
        ]

    # Required Event IDs give strongest evidence.
    if required_event_ids:

        required = set(
            required_event_ids
        )

        event_matches = [
            row
            for row in channel_matches
            if row["event_id"]
            in required
        ]

        if event_matches:

            return (
                "exact_event_id",
                event_matches,
            )

        # Do not count EventID from another
        # provider/channel as exact evidence.
        return (
            "no_exact_event_id",
            [],
        )

    # No explicit Event ID: channel existence
    # provides source-level evidence only.
    if channel_matches:

        return (
            "channel_observed",
            channel_matches,
        )

    return (
        "none",
        [],
    )


# ---------------------------------------------------------
# Build expanded evidence table
# ---------------------------------------------------------

evidence_rows = []
unresolved_components = []


for technique in techniques:

    technique_id = technique[
        "technique_id"
    ]

    component_ids = (
        technique.get(
            "data_components"
        )
        or []
    )

    # Keep technique visible even if ATT&CK
    # supplies no Data Component.
    if not component_ids:

        evidence_rows.append(
            {
                "technique_id":
                    technique_id,
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
                "data_component_id": "",
                "data_component_name": "",
                "mitre_log_source": "",
                "mitre_channel": "",
                "required_event_ids": "",
                "capability_hint": "",
                "bots_evidence_status":
                    "not_specified",
                "bots_matching_sourcetypes":
                    "",
                "bots_capability_coverage_pct":
                    "",
                "evtx_evidence_status":
                    "not_specified",
                "evtx_matching_event_ids":
                    "",
                "evtx_matching_channels":
                    "",
                "evtx_matching_categories":
                    "",
                "evtx_event_count": 0,
                "telemetry_evidence_status":
                    "requirement_unspecified",
                "evidence_sources": "",
                "evidence_strength": 0,
            }
        )

        continue


    for component_id in component_ids:

        component = component_by_id.get(
            component_id
        )

        if component is None:

            unresolved_components.append(
                {
                    "technique_id":
                        technique_id,
                    "component_id":
                        component_id,
                }
            )

            continue

        component_name = component.get(
            "name",
            "",
        )

        component_description = (
            component.get(
                "description",
                "",
            )
        )

        capability_hint = (
            infer_capability(
                component_name,
                component_description,
            )
        )

        raw = (
            component.get(
                "raw",
                {}
            )
            or {}
        )

        log_sources = (
            raw.get(
                "x_mitre_log_sources"
            )
            or []
        )

        # Preserve Data Component even where
        # ATT&CK does not expose a concrete
        # x_mitre_log_sources entry.
        if not log_sources:

            log_sources = [
                {
                    "name": "",
                    "channel": "",
                }
            ]


        for log_source in log_sources:

            source_name = (
                log_source.get(
                    "name",
                    "",
                )
                or ""
            )

            channel_text = (
                log_source.get(
                    "channel",
                    "",
                )
                or ""
            )

            event_ids = (
                extract_event_ids(
                    channel_text
                )
            )

            # -----------------------------
            # BOTS evidence
            # -----------------------------

            (
                bots_matches,
                bots_status,
            ) = bots_source_matches(
                source_name
            )

            coverage_values = []

            if capability_hint:

                for st in bots_matches:

                    cap_row = (
                        bots_capability_lookup.get(
                            (
                                st,
                                capability_hint,
                            )
                        )
                    )

                    if cap_row:

                        coverage_values.append(
                            float(
                                cap_row[
                                    "availability_weighted_coverage_pct"
                                ]
                                or 0
                            )
                        )

            bots_coverage = (
                max(
                    coverage_values
                )
                if coverage_values
                else 0.0
            )

            # -----------------------------
            # EVTX evidence
            # -----------------------------

            (
                evtx_status,
                evtx_matches,
            ) = evtx_match(
                source_name,
                event_ids,
            )

            evtx_event_ids = sorted(
                {
                    row["event_id"]
                    for row in evtx_matches
                },
                key=lambda x: int(x),
            )

            evtx_channels = sorted(
                {
                    row["channel"]
                    for row in evtx_matches
                }
            )

            evtx_categories = sorted(
                {
                    row[
                        "canonical_category"
                    ]
                    for row in evtx_matches
                }
            )

            evtx_event_count = sum(
                int(
                    row["event_count"]
                )
                for row in evtx_matches
            )

            # -----------------------------
            # Evidence classification
            # -----------------------------

            exact_bots = (
                bots_status
                == "exact_source"
            )

            family_bots = (
                bots_status
                not in {
                    "none",
                    "exact_source",
                }
            )

            exact_evtx = (
                evtx_status
                == "exact_event_id"
            )

            channel_evtx = (
                evtx_status
                == "channel_observed"
            )

            requirement_present = bool(
                source_name
                or channel_text
            )

            if exact_evtx or exact_bots:

                telemetry_status = (
                    "available"
                )

                strength = 3

            elif family_bots or channel_evtx:

                telemetry_status = (
                    "partial"
                )

                strength = 2

            elif requirement_present:

                telemetry_status = (
                    "not_observed"
                )

                strength = 0

            else:

                telemetry_status = (
                    "requirement_unspecified"
                )

                strength = 0

            evidence_sources = []

            if bots_status != "none":
                evidence_sources.append(
                    "BOTS"
                )

            if evtx_status in {
                "exact_event_id",
                "channel_observed",
            }:
                evidence_sources.append(
                    "EVTX"
                )

            evidence_rows.append(
                {
                    "technique_id":
                        technique_id,
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
                    "data_component_id":
                        component_id,
                    "data_component_name":
                        component_name,
                    "mitre_log_source":
                        source_name,
                    "mitre_channel":
                        channel_text,
                    "required_event_ids":
                        " | ".join(
                            event_ids
                        ),
                    "capability_hint":
                        capability_hint,
                    "bots_evidence_status":
                        bots_status,
                    "bots_matching_sourcetypes":
                        " | ".join(
                            bots_matches
                        ),
                    "bots_capability_coverage_pct":
                        round(
                            bots_coverage,
                            6,
                        ),
                    "evtx_evidence_status":
                        evtx_status,
                    "evtx_matching_event_ids":
                        " | ".join(
                            evtx_event_ids
                        ),
                    "evtx_matching_channels":
                        " | ".join(
                            evtx_channels
                        ),
                    "evtx_matching_categories":
                        " | ".join(
                            evtx_categories
                        ),
                    "evtx_event_count":
                        evtx_event_count,
                    "telemetry_evidence_status":
                        telemetry_status,
                    "evidence_sources":
                        " | ".join(
                            evidence_sources
                        ),
                    "evidence_strength":
                        strength,
                }
            )


# ---------------------------------------------------------
# Validate / write expanded evidence
# ---------------------------------------------------------

evidence_fields = [
    "technique_id",
    "technique_name",
    "platforms",
    "tactics",
    "data_component_id",
    "data_component_name",
    "mitre_log_source",
    "mitre_channel",
    "required_event_ids",
    "capability_hint",
    "bots_evidence_status",
    "bots_matching_sourcetypes",
    "bots_capability_coverage_pct",
    "evtx_evidence_status",
    "evtx_matching_event_ids",
    "evtx_matching_channels",
    "evtx_matching_categories",
    "evtx_event_count",
    "telemetry_evidence_status",
    "evidence_sources",
    "evidence_strength",
]


with EVIDENCE_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=evidence_fields,
    )

    writer.writeheader()
    writer.writerows(
        evidence_rows
    )


# ---------------------------------------------------------
# Technique-level factual summary
#
# Important:
# This is NOT the project's weighted
# Telemetry Readiness Score.
# ---------------------------------------------------------

rows_by_technique = defaultdict(
    list
)

for row in evidence_rows:

    rows_by_technique[
        row["technique_id"]
    ].append(row)


technique_rows = []


for technique in techniques:

    tid = technique[
        "technique_id"
    ]

    rows = rows_by_technique.get(
        tid,
        [],
    )

    statuses = [
        row[
            "telemetry_evidence_status"
        ]
        for row in rows
    ]

    components_referenced = {
        row["data_component_id"]
        for row in rows
        if row["data_component_id"]
    }

    components_observed = {
        row["data_component_id"]
        for row in rows
        if (
            row["data_component_id"]
            and row[
                "telemetry_evidence_status"
            ]
            in {
                "available",
                "partial",
            }
        )
    }

    if "available" in statuses:

        overall = "available"

    elif "partial" in statuses:

        overall = "partial"

    elif "not_observed" in statuses:

        overall = "not_observed"

    else:

        overall = (
            "requirement_unspecified"
        )

    evidence_sources = sorted(
        {
            source
            for row in rows
            for source in (
                row[
                    "evidence_sources"
                ].split(" | ")
                if row[
                    "evidence_sources"
                ]
                else []
            )
        }
    )

    max_strength = max(
        (
            int(
                row[
                    "evidence_strength"
                ]
            )
            for row in rows
        ),
        default=0,
    )

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
                len(
                    components_referenced
                ),
            "data_components_with_evidence":
                len(
                    components_observed
                ),
            "requirement_rows":
                len(rows),
            "available_rows":
                statuses.count(
                    "available"
                ),
            "partial_rows":
                statuses.count(
                    "partial"
                ),
            "not_observed_rows":
                statuses.count(
                    "not_observed"
                ),
            "unspecified_rows":
                statuses.count(
                    "requirement_unspecified"
                ),
            "telemetry_evidence_status":
                overall,
            "evidence_sources":
                " | ".join(
                    evidence_sources
                ),
            "max_evidence_strength":
                max_strength,
        }
    )


technique_fields = [
    "technique_id",
    "technique_name",
    "platforms",
    "tactics",
    "data_components_referenced",
    "data_components_with_evidence",
    "requirement_rows",
    "available_rows",
    "partial_rows",
    "not_observed_rows",
    "unspecified_rows",
    "telemetry_evidence_status",
    "evidence_sources",
    "max_evidence_strength",
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
    writer.writerows(
        technique_rows
    )


# ---------------------------------------------------------
# Quality gates
# ---------------------------------------------------------

allowed_statuses = {
    "available",
    "partial",
    "not_observed",
    "requirement_unspecified",
}


invalid_status_rows = [
    row
    for row in evidence_rows
    if row[
        "telemetry_evidence_status"
    ]
    not in allowed_statuses
]


duplicate_keys = []

seen = set()

for row in evidence_rows:

    key = (
        row["technique_id"],
        row["data_component_id"],
        row["mitre_log_source"],
        row["mitre_channel"],
    )

    if key in seen:
        duplicate_keys.append(
            key
        )

    seen.add(key)


technique_status_counts = defaultdict(
    int
)

for row in technique_rows:

    technique_status_counts[
        row[
            "telemetry_evidence_status"
        ]
    ] += 1


summary = {
    "artifact":
        "Integrated Telemetry Evidence",
    "artifact_version":
        "1.0.0",
    "attack_version":
        "19.1",
    "active_techniques":
        len(techniques),
    "attack_data_components":
        len(components),
    "evidence_rows":
        len(evidence_rows),
    "technique_summary_rows":
        len(technique_rows),
    "bots_sourcetypes":
        len(bots_inventory),
    "bots_unique_searchable_events":
        sum(
            int(
                float(
                    row[
                        "unique_events"
                    ]
                )
            )
            for row in bots_inventory
        ),
    "evtx_canonical_events":
        evtx_summary.get(
            "canonical_event_count",
            0,
        ),
    "evtx_event_profile_rows":
        len(evtx_profile),
    "unresolved_component_refs":
        len(
            unresolved_components
        ),
    "duplicate_evidence_keys":
        len(
            duplicate_keys
        ),
    "invalid_status_rows":
        len(
            invalid_status_rows
        ),
    "technique_status_counts":
        dict(
            sorted(
                technique_status_counts.items()
            )
        ),
    "important_note":
        (
            "telemetry_evidence_status is factual "
            "dataset evidence, not the Phase 3 "
            "weighted Telemetry Readiness score."
        ),
    "status":
        (
            "PASS"
            if (
                len(techniques) == 697
                and
                len(technique_rows) == 697
                and
                len(unresolved_components) == 0
                and
                len(duplicate_keys) == 0
                and
                len(invalid_status_rows) == 0
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


print(
    json.dumps(
        summary,
        indent=2,
    )
)

print()
print(
    f"Evidence:  {EVIDENCE_OUTPUT}"
)
print(
    f"Techniques:{TECHNIQUE_OUTPUT}"
)
print(
    f"Summary:   {SUMMARY_OUTPUT}"
)
