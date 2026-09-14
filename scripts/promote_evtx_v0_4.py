from __future__ import annotations

import csv
import gzip
import hashlib
import json
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jsonschema.validators import validator_for


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent

TELEMETRY = ROOT / "data" / "processed" / "telemetry"
REPORTS = ROOT / "reports" / "evtx_full_v0_4"
RAW_ROOT = WORKSPACE / "datasets" / "raw" / "EVTX-ATTACK-SAMPLES"

CANDIDATE = (
    TELEMETRY
    / "evtx_canonical_events_full_v0_4_candidate.jsonl.gz"
)

DIRECT_INVENTORY = (
    TELEMETRY
    / "evtx_unparsed_files.csv"
)

SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "canonical_event.schema.json"
)

ACTIVE_CANONICAL = (
    TELEMETRY
    / "evtx_canonical_events.jsonl.gz"
)

ACTIVE_FLAT = (
    TELEMETRY
    / "evtx_canonical_events_flat.csv.gz"
)

ACTIVE_PROFILE = (
    TELEMETRY
    / "evtx_event_id_profile.csv"
)

ACTIVE_INVENTORY = (
    TELEMETRY
    / "evtx_source_file_inventory.csv"
)

ACTIVE_UNPARSED = (
    TELEMETRY
    / "evtx_unparsed_files.csv"
)

ACTIVE_TACTIC = (
    TELEMETRY
    / "evtx_tactic_profile.csv"
)

ACTIVE_SUMMARY = (
    TELEMETRY
    / "evtx_summary.json"
)

CANONICAL_FIELD_PROFILE = (
    TELEMETRY
    / "evtx_canonical_field_profile_v0_4.csv"
)

VALIDATION_REPORT = (
    REPORTS
    / "evtx_v0_4_promotion_validation.json"
)

PIPELINE_VERSION = "0.4.0"
EXPECTED_EVENTS = 37364
EXPECTED_FILES = 278
EXPECTED_COMMIT = "4ceed2f4706daf601c212a8f91c113dd85349a2c"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def load_events(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def flatten(obj, prefix=""):
    result = {}

    if isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)

            if key == "raw":
                # Raw payload is retained in the canonical JSONL,
                # but not exploded into thousands of profile columns.
                continue

            result.update(flatten(value, name))

    elif isinstance(obj, list):
        result[prefix] = " | ".join(str(x) for x in obj)

    else:
        result[prefix] = obj

    return result


# ---------------------------------------------------------
# Validate candidate
# ---------------------------------------------------------

schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
Validator = validator_for(schema)
Validator.check_schema(schema)
validator = Validator(schema)

events = []
uids = set()
source_files = set()

schema_failures = 0
duplicate_uids = 0

categories = Counter()
actions = Counter()
warnings = Counter()

timestamp_values = []
quality_scores = []

explicit_attack_events = 0


for event in load_events(CANDIDATE):

    errors = list(validator.iter_errors(event))

    if errors:
        schema_failures += 1

    uid = event["event_uid"]

    if uid in uids:
        duplicate_uids += 1

    uids.add(uid)

    source_file = (
        event.get("lineage", {})
        .get("source_file")
    )

    if source_file:
        source_files.add(source_file)

    categories[
        event["event"]["category"]
    ] += 1

    actions[
        event["event"]["action"]
    ] += 1

    for warning in (
        event.get("data_quality", {})
        .get("mapping_warnings", [])
    ):
        warnings[warning] += 1

    timestamp = event.get("timestamp")

    if timestamp:
        timestamp_values.append(timestamp)

    score = (
        event.get("data_quality", {})
        .get("quality_score")
    )

    if score is not None:
        quality_scores.append(float(score))

    if (
        event.get("attack", {})
        .get("technique_ids")
    ):
        explicit_attack_events += 1

    events.append(event)


candidate_valid = (
    len(events) == EXPECTED_EVENTS
    and len(uids) == EXPECTED_EVENTS
    and len(source_files) == EXPECTED_FILES
    and schema_failures == 0
    and duplicate_uids == 0
)

if not candidate_valid:
    raise RuntimeError(
        "EVTX v0.4 candidate failed promotion gates."
    )


# ---------------------------------------------------------
# Backup v0.3 artifacts
# ---------------------------------------------------------

backup_dir = (
    TELEMETRY
    / "archive"
    / "evtx_v0_3_0"
)

backup_dir.mkdir(
    parents=True,
    exist_ok=True,
)

for path in [
    ACTIVE_CANONICAL,
    ACTIVE_FLAT,
    ACTIVE_PROFILE,
    ACTIVE_INVENTORY,
    ACTIVE_UNPARSED,
    ACTIVE_TACTIC,
    ACTIVE_SUMMARY,
    TELEMETRY / "evtx_field_profile.csv",
]:

    if path.exists():

        target = backup_dir / path.name

        if not target.exists():
            shutil.copy2(path, target)


# ---------------------------------------------------------
# Identify direct-parsed files
# ---------------------------------------------------------

old_unparsed_backup = (
    backup_dir
    / "evtx_unparsed_files.csv"
)

direct_paths = set()

if old_unparsed_backup.exists():

    with old_unparsed_backup.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        for row in csv.DictReader(f):
            direct_paths.add(
                row["relative_path"].replace("\\", "/")
            )

if len(direct_paths) != 29:
    raise RuntimeError(
        f"Expected 29 direct-parsed files, found {len(direct_paths)}"
    )


# ---------------------------------------------------------
# Event counts by source
# ---------------------------------------------------------

events_by_source = Counter(
    event["lineage"]["source_file"]
    for event in events
)


# ---------------------------------------------------------
# Build source inventory 278/278
# ---------------------------------------------------------

inventory_rows = []

for path in sorted(
    RAW_ROOT.rglob("*.evtx")
):

    relative = (
        path.relative_to(RAW_ROOT)
        .as_posix()
    )

    count = events_by_source.get(
        relative,
        0,
    )

    method = (
        "direct_python_evtx"
        if relative in direct_paths
        else "repository_published_csv"
    )

    inventory_rows.append(
        {
            "relative_path": relative,
            "file_name": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "preparation_method": method,
            "canonical_event_count": count,
            "represented": count > 0,
        }
    )


if len(inventory_rows) != 278:
    raise RuntimeError(
        f"Expected 278 raw files, found {len(inventory_rows)}"
    )

if not all(row["represented"] for row in inventory_rows):
    raise RuntimeError(
        "At least one raw EVTX file has no canonical events."
    )


with ACTIVE_INVENTORY.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(inventory_rows[0].keys()),
    )

    writer.writeheader()
    writer.writerows(inventory_rows)


# Zero-row unparsed artifact, preserving explicit status.
with ACTIVE_UNPARSED.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "relative_path",
            "file_name",
            "reason",
        ],
    )

    writer.writeheader()


# ---------------------------------------------------------
# Promote canonical JSONL atomically
# ---------------------------------------------------------

temp_canonical = (
    TELEMETRY
    / "evtx_canonical_events.v0_4.tmp.jsonl.gz"
)

shutil.copy2(
    CANDIDATE,
    temp_canonical,
)

if ACTIVE_CANONICAL.exists():
    ACTIVE_CANONICAL.unlink()

temp_canonical.replace(
    ACTIVE_CANONICAL
)


# ---------------------------------------------------------
# Build flat canonical CSV
# ---------------------------------------------------------

flat_rows = []

for event in events:

    flat_rows.append(
        {
            "event_uid": event["event_uid"],
            "timestamp": event["timestamp"],
            "event_id": event["event"]["id"],
            "event_category": event["event"]["category"],
            "event_action": event["event"]["action"],
            "provider": event["event"]["provider"],
            "channel": event["event"]["channel"],
            "host_name": event["host"]["name"],
            "user_name": event["user"]["name"],
            "user_domain": event["user"]["domain"],
            "process_name": event["process"]["name"],
            "process_executable": event["process"]["executable"],
            "process_command_line": event["process"]["command_line"],
            "parent_process_name": event["process"]["parent"]["name"],
            "source_ip": event["source"]["ip"],
            "source_port": event["source"]["port"],
            "destination_ip": event["destination"]["ip"],
            "destination_port": event["destination"]["port"],
            "file_path": event["file"]["path"],
            "registry_path": event["registry"]["path"],
            "attack_tactics": "|".join(
                event["attack"].get("tactics", [])
            ),
            "attack_technique_ids": "|".join(
                event["attack"].get("technique_ids", [])
            ),
            "source_file": event["lineage"]["source_file"],
            "pipeline_version": event["lineage"]["pipeline_version"],
            "quality_score": event["data_quality"]["quality_score"],
            "mapping_warnings": "|".join(
                event["data_quality"]["mapping_warnings"]
            ),
        }
    )


with gzip.open(
    ACTIVE_FLAT,
    "wt",
    encoding="utf-8",
    newline="",
) as gz:

    writer = csv.DictWriter(
        gz,
        fieldnames=list(flat_rows[0].keys()),
    )

    writer.writeheader()
    writer.writerows(flat_rows)


# ---------------------------------------------------------
# Event-ID profile
# ---------------------------------------------------------

profile = defaultdict(
    lambda: {
        "count": 0,
        "files": set(),
        "category": "",
        "action": "",
    }
)

for event in events:

    ev = event["event"]

    key = (
        ev.get("provider") or "",
        ev.get("provider_normalized") or "",
        ev.get("channel") or "",
        str(ev.get("id") or ""),
    )

    item = profile[key]

    item["count"] += 1
    item["files"].add(
        event["lineage"]["source_file"]
    )
    item["category"] = ev["category"]
    item["action"] = ev["action"]


profile_rows = []

for key, item in profile.items():

    provider, normalized, channel, event_id = key

    profile_rows.append(
        {
            "provider": provider,
            "provider_normalized": normalized,
            "channel": channel,
            "event_id": event_id,
            "event_count": item["count"],
            "unique_files": len(item["files"]),
            "canonical_category": item["category"],
            "canonical_action": item["action"],
        }
    )


profile_rows.sort(
    key=lambda row: -row["event_count"]
)


with ACTIVE_PROFILE.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(profile_rows[0].keys()),
    )

    writer.writeheader()
    writer.writerows(profile_rows)


# ---------------------------------------------------------
# Source-tactic profile
# ---------------------------------------------------------

tactic_groups = defaultdict(
    lambda: {
        "events": 0,
        "files": set(),
        "event_ids": set(),
        "channels": set(),
    }
)


for event in events:

    tactics = (
        event.get("attack", {})
        .get("tactics")
        or [""]
    )

    for tactic in tactics:

        item = tactic_groups[tactic]

        item["events"] += 1

        item["files"].add(
            event["lineage"]["source_file"]
        )

        item["event_ids"].add(
            str(event["event"]["id"])
        )

        item["channels"].add(
            event["event"].get("channel") or ""
        )


tactic_rows = []

for tactic, item in tactic_groups.items():

    tactic_rows.append(
        {
            "EVTX_Tactic": tactic,
            "event_count": item["events"],
            "unique_files": len(item["files"]),
            "unique_event_ids": len(item["event_ids"]),
            "unique_channels": len(item["channels"]),
        }
    )


tactic_rows.sort(
    key=lambda row: -row["event_count"]
)


with ACTIVE_TACTIC.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(tactic_rows[0].keys()),
    )

    writer.writeheader()
    writer.writerows(tactic_rows)


# ---------------------------------------------------------
# Canonical field coverage profile
# ---------------------------------------------------------

field_non_null = Counter()
field_values = defaultdict(set)

for event in events:

    flattened = flatten(event)

    for field, value in flattened.items():

        if value in (None, "", [], {}):
            continue

        field_non_null[field] += 1

        if len(field_values[field]) < 10000:
            try:
                field_values[field].add(
                    json.dumps(
                        value,
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                )
            except TypeError:
                field_values[field].add(str(value))


field_rows = []

for field in sorted(field_non_null):

    count = field_non_null[field]

    field_rows.append(
        {
            "canonical_field": field,
            "non_null_count": count,
            "coverage_ratio": round(
                count / EXPECTED_EVENTS,
                6,
            ),
            "observed_unique_values_capped": len(
                field_values[field]
            ),
        }
    )


with CANONICAL_FIELD_PROFILE.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(field_rows[0].keys()),
    )

    writer.writeheader()
    writer.writerows(field_rows)


# ---------------------------------------------------------
# v0.4 summary
# ---------------------------------------------------------

now = datetime.now(timezone.utc).isoformat().replace(
    "+00:00",
    "Z",
)

summary = {
    "pipeline_version": PIPELINE_VERSION,
    "source_repository_commit": EXPECTED_COMMIT,
    "raw_evtx_file_count": 278,
    "raw_evtx_size_bytes": sum(
        row["size_bytes"]
        for row in inventory_rows
    ),
    "published_csv_source_files": 249,
    "direct_python_evtx_source_files": 29,
    "total_source_files_represented": 278,
    "published_csv_canonical_events": 4633,
    "direct_python_evtx_canonical_events": 32731,
    "canonical_event_count": len(events),
    "unique_event_uid_count": len(uids),
    "canonical_event_category_counts": dict(
        sorted(categories.items())
    ),
    "canonical_event_action_counts": dict(
        actions.most_common()
    ),
    "mapping_warning_counts": dict(
        warnings.most_common()
    ),
    "schema_failure_count": schema_failures,
    "duplicate_event_uid_count": duplicate_uids,
    "unrepresented_raw_file_count": 0,
    "timestamp_min_utc": min(timestamp_values),
    "timestamp_max_utc": max(timestamp_values),
    "mean_quality_score": round(
        sum(quality_scores) / len(quality_scores),
        6,
    ),
    "explicit_technique_mapped_event_count": explicit_attack_events,
    "mapping_limitations": {
        "rpc_etw_unmapped_semantics": (
            "Microsoft-Windows-RPC ETW events without an approved "
            "canonical semantic mapping are retained as category=other "
            "with raw XML/source fields preserved."
        ),
        "network_missing_endpoint_warning": (
            "Some BITS/RdpCoreTS network-category records do not expose "
            "a usable source/destination IP or share in mapped source fields; "
            "no endpoint values are synthesized."
        ),
    },
    "generated_at": now,
    "status": "PASS",
}


ACTIVE_SUMMARY.write_text(
    json.dumps(
        summary,
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)


validation = {
    "artifact": "EVTX v0.4 Promotion Validation",
    "canonical_events": len(events),
    "unique_event_uids": len(uids),
    "source_files_represented": len(source_files),
    "schema_failures": schema_failures,
    "duplicate_event_uids": duplicate_uids,
    "unrepresented_files": sum(
        1
        for row in inventory_rows
        if not row["represented"]
    ),
    "active_canonical_sha256": sha256_file(
        ACTIVE_CANONICAL
    ),
    "status": "PASS",
}


VALIDATION_REPORT.write_text(
    json.dumps(
        validation,
        indent=2,
    ),
    encoding="utf-8",
)


print(json.dumps(summary, indent=2))
print()
print("=== PROMOTION VALIDATION ===")
print(json.dumps(validation, indent=2))
print()
print(f"Backup v0.3:       {backup_dir}")
print(f"Active canonical:  {ACTIVE_CANONICAL}")
print(f"Active summary:    {ACTIVE_SUMMARY}")
print(f"Validation report: {VALIDATION_REPORT}")
