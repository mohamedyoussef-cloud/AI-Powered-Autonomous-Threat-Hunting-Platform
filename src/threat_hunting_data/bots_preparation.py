from __future__ import annotations

from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from typing import Any, Iterable

import yaml


DATA_FILE_SUFFIXES = {
    "SourceTypes.data": ("sourcetype", "sourcetype::"),
    "Hosts.data": ("host", "host::"),
    "Sources.data": ("source", "source::"),
}


def utc_iso(epoch: int | str | None) -> str:
    if epoch in (None, ""):
        return ""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_splunk_metadata_data(payload: bytes, prefix: str) -> tuple[dict[str, int], list[dict[str, int | str]]]:
    """Parse Splunk bucket metadata files such as SourceTypes.data.

    The first row is a bucket summary. Subsequent rows contain one value and its
    event count/time range. This parser deliberately does not parse raw journals.
    """
    text = payload.decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return {}, []

    def parse_line(line: str) -> dict[str, int | str] | None:
        parts = line.split("\t")
        if len(parts) < 6:
            return None
        try:
            return {
                "local_id": int(parts[0].strip()),
                "name": parts[1].strip(),
                "event_count": int(parts[2].strip()),
                "earliest_epoch": int(parts[3].strip()),
                "latest_epoch": int(parts[4].strip()),
                "modtime_epoch": int(parts[5].strip()),
            }
        except (TypeError, ValueError):
            return None

    first = parse_line(lines[0])
    summary = {
        "distinct_count": int(first["name"]) if first and str(first["name"]).isdigit() else 0,
        "event_count": int(first["event_count"]) if first else 0,
        "earliest_epoch": int(first["earliest_epoch"]) if first else 0,
        "latest_epoch": int(first["latest_epoch"]) if first else 0,
        "modtime_epoch": int(first["modtime_epoch"]) if first else 0,
    }

    rows: list[dict[str, int | str]] = []
    for line in lines[1:]:
        row = parse_line(line)
        if not row:
            continue
        name = str(row["name"])
        if prefix and name.startswith(prefix):
            row["name"] = name[len(prefix) :]
        rows.append(row)
    return summary, rows


def classify_sourcetype(sourcetype: str) -> tuple[str, str, str]:
    """Return preliminary canonical domain, event family, and mapping confidence.

    The result is an inventory-level classification. It is not a substitute for
    event-level field profiling after the dataset is loaded into Splunk.
    """
    value = sourcetype.lower()
    if value == "ess_content_importer":
        return "administrative", "content_metadata", "high"
    if any(token in value for token in ("aad", "okta", "signin", "authentication", "duo")):
        return "identity", "authentication", "medium"
    if any(token in value for token in ("stream:http", "iis", "access_combined", "apache", "nginx")):
        return "web", "web_activity", "medium"
    if any(token in value for token in ("stream:smtp", "exchange", "exch:", "email", "messagetrace")):
        return "email", "email_activity", "medium"
    if any(token in value for token in ("stream:mysql", "rds:audit", "sql", "database")):
        return "database", "database_activity", "medium"
    if any(token in value for token in ("sysmon", "wineventlog", "winhostmon", "osquery", "symantec", "powershell", "code42")):
        return "endpoint", "endpoint_activity", "medium"
    if any(token in value for token in ("aws:", "azure", "ms:o365", "cloudtrail", "cloudwatch", "config:")):
        return "cloud", "cloud_activity", "medium"
    if any(token in value for token in ("stream:", "suricata", "cisco:asa", "firewall", "netflow", "bro:", "zeek")):
        return "network", "network_activity", "medium"
    if any(token in value for token in ("linux", "unix", "auditd", "syslog", "linux_secure", "bash_history", "cron", "dpkg", "lastlog", "lsof", "netstat", "interfaces", "openports")):
        return "host_os", "operating_system", "low"
    return "other", "unclassified", "low"


def hash_file(path: Path) -> dict[str, str]:
    hashes = {"md5": hashlib.md5(), "sha256": hashlib.sha256()}
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in hashes.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in hashes.items()}


def _write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _aggregate(metadata_rows: list[tuple[str, list[dict[str, int | str]]]]) -> list[dict[str, Any]]:
    aggregate: dict[str, dict[str, int | None]] = defaultdict(
        lambda: {"event_count": 0, "bucket_count": 0, "earliest_epoch": None, "latest_epoch": None}
    )
    for _bucket, rows in metadata_rows:
        for row in rows:
            name = str(row["name"])
            target = aggregate[name]
            target["event_count"] = int(target["event_count"] or 0) + int(row["event_count"])
            target["bucket_count"] = int(target["bucket_count"] or 0) + 1
            earliest = int(row["earliest_epoch"])
            latest = int(row["latest_epoch"])
            target["earliest_epoch"] = earliest if target["earliest_epoch"] is None else min(int(target["earliest_epoch"]), earliest)
            target["latest_epoch"] = latest if target["latest_epoch"] is None else max(int(target["latest_epoch"]), latest)

    output = []
    for name, values in sorted(aggregate.items(), key=lambda item: (-int(item[1]["event_count"] or 0), item[0])):
        output.append(
            {
                "name": name,
                **values,
                "earliest_utc": utc_iso(values["earliest_epoch"]),
                "latest_utc": utc_iso(values["latest_epoch"]),
            }
        )
    return output


def _parse_props(props: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    stanza = ""
    aliases: list[dict[str, str]] = []
    derived: list[dict[str, str]] = []
    for raw_line in props.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            stanza = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.upper().startswith("FIELDALIAS-"):
            for component in value.split(","):
                match = re.match(r"\s*[\"']?(.+?)[\"']?\s+as\s+([A-Za-z0-9_.{}-]+)\s*$", component, re.IGNORECASE)
                if match:
                    aliases.append(
                        {
                            "sourcetype_stanza": stanza,
                            "source_field": match.group(1).strip(),
                            "alias_field": match.group(2).strip(),
                            "config_key": key,
                        }
                    )
        elif key.upper().startswith("EVAL-"):
            derived.append({"sourcetype_stanza": stanza, "derived_field": key[5:], "expression": value})
    return aliases, derived


def _update_registry(project_root: Path, summary: dict[str, Any]) -> None:
    path = project_root / "configs" / "dataset_registry.yaml"
    registry = yaml.safe_load(path.read_text(encoding="utf-8"))
    source = registry["sources"]["bots_v3"]
    source.update(
        {
            "observed_version": "v3",
            "source_archive_md5": summary["md5"],
            "source_archive_sha256": summary["sha256"],
            "index_name": summary["index_name"],
            "active_bucket_count": summary["active_bucket_count"],
            "disabled_bucket_count": summary["disabled_bucket_count"],
            "manifest_event_count": summary["manifest_event_count"],
            "scenario_telemetry_event_count": summary["scenario_telemetry_event_count"],
            "unique_sourcetypes": summary["unique_sourcetypes"],
            "unique_hosts": summary["unique_hosts"],
            "unique_sources": summary["unique_sources"],
            "processing_status": "source_profiled_v0.4.0; full_event_export_and_normalization_pending_splunk_runtime",
        }
    )
    path.write_text(yaml.safe_dump(registry, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _update_inventory(project_root: Path, summary: dict[str, Any]) -> None:
    path = project_root / "reports" / "data_inventory.csv"
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
        fields = list(rows[0].keys())
    for row in rows:
        if row["dataset"] == "BOTS v3":
            row.update(
                {
                    "version_or_commit": "v3",
                    "source_status": "received; integrity verified; pre-indexed source metadata processed",
                    "source_sha256": summary["sha256"],
                    "raw_artifact": "user-supplied botsv3_data_set.tgz (not redistributed)",
                    "source_units": str(summary["manifest_event_count"]),
                    "accepted_processed_units": str(summary["active_bucket_count"]),
                    "quarantined_or_inactive_units": str(summary["disabled_bucket_count"]),
                    "notes": (
                        f"{summary['unique_sourcetypes']} sourcetypes, {summary['unique_hosts']} hosts, "
                        f"{summary['unique_sources']} sources profiled from bucket metadata; event export requires Splunk runtime."
                    ),
                }
            )
    _write_csv(path, rows, fields)


def prepare_botsv3_dataset(source_archive: Path, project_root: Path) -> dict[str, Any]:
    source_archive = source_archive.resolve()
    project_root = project_root.resolve()
    telemetry_dir = project_root / "data" / "processed" / "telemetry" / "botsv3"
    report_dir = project_root / "reports"
    docs_dir = project_root / "docs"
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    digests = hash_file(source_archive)
    bucket_rows: list[dict[str, Any]] = []
    disabled_rows: list[dict[str, Any]] = []
    metadata: dict[str, list[tuple[str, list[dict[str, int | str]]]]] = defaultdict(list)
    disabled_metadata: dict[str, list[tuple[str, list[dict[str, int | str]]]]] = defaultdict(list)
    props = transforms = indexes = readme = manifest_text = ""

    with tarfile.open(source_archive, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        config_paths = {
            "props": "botsv3_data_set/default/props.conf",
            "transforms": "botsv3_data_set/default/transforms.conf",
            "indexes": "botsv3_data_set/default/indexes.conf",
            "readme": "botsv3_data_set/README.txt",
            "manifest": "botsv3_data_set/var/lib/splunk/botsv3/db/.bucketManifest",
        }
        values: dict[str, str] = {}
        for key, member_name in config_paths.items():
            if member_name not in names:
                raise ValueError(f"Required BOTS v3 member is missing: {member_name}")
            extracted = archive.extractfile(member_name)
            if extracted is None:
                raise ValueError(f"Cannot read BOTS v3 member: {member_name}")
            values[key] = extracted.read().decode("utf-8", errors="replace")
        props, transforms, indexes, readme, manifest_text = (
            values["props"], values["transforms"], values["indexes"], values["readme"], values["manifest"]
        )

        for row in csv.DictReader(io.StringIO(manifest_text)):
            converted: dict[str, Any] = dict(row)
            for field in (
                "raw_size", "event_count", "host_count", "source_count", "sourcetype_count", "size_on_disk",
                "modtime", "frozen_in_cluster", "tsidx_minified", "journal_size",
            ):
                converted[field] = int(converted[field])
            match = re.fullmatch(r"db_(\d+)_(\d+)_(\d+)", row["path"])
            converted["latest_epoch"] = int(match.group(1)) if match else None
            converted["earliest_epoch"] = int(match.group(2)) if match else None
            converted["latest_utc"] = utc_iso(converted["latest_epoch"])
            converted["earliest_utc"] = utc_iso(converted["earliest_epoch"])
            bucket_rows.append(converted)

        active_buckets = {row["path"] for row in bucket_rows}
        seen_bucket_dirs: set[str] = set()
        for member in members:
            if not member.isfile():
                continue
            bucket_name = member.name.split("/")[-2] if "/db/" in member.name or "/colddb/" in member.name else ""
            if bucket_name.startswith("db_") or bucket_name.startswith("DISABLED-db_"):
                seen_bucket_dirs.add(bucket_name)
            for suffix, (kind, prefix) in DATA_FILE_SUFFIXES.items():
                if not member.name.endswith("/" + suffix):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                summary_row, rows = parse_splunk_metadata_data(extracted.read(), prefix)
                if bucket_name in active_buckets:
                    metadata[kind].append((bucket_name, rows))
                else:
                    disabled_metadata[kind].append((bucket_name, rows))
                    if kind == "sourcetype":
                        disabled_rows.append(
                            {
                                "bucket": bucket_name,
                                "event_count": summary_row.get("event_count", 0),
                                "earliest_epoch": summary_row.get("earliest_epoch", 0),
                                "latest_epoch": summary_row.get("latest_epoch", 0),
                                "earliest_utc": utc_iso(summary_row.get("earliest_epoch", 0)),
                                "latest_utc": utc_iso(summary_row.get("latest_epoch", 0)),
                                "reason": "bucket_directory_not_present_in_active_bucket_manifest",
                            }
                        )

        member_count = len(members)
        file_count = sum(member.isfile() for member in members)
        directory_count = sum(member.isdir() for member in members)
        uncompressed_bytes = sum(member.size for member in members if member.isfile())
        journal_count = sum(member.isfile() and member.name.endswith("/rawdata/journal.gz") for member in members)

    sourcetypes = _aggregate(metadata["sourcetype"])
    hosts = _aggregate(metadata["host"])
    sources = _aggregate(metadata["source"])

    sourcetype_rows: list[dict[str, Any]] = []
    for row in sourcetypes:
        domain, family, confidence = classify_sourcetype(str(row["name"]))
        sourcetype_rows.append(
            {
                "sourcetype": row["name"],
                "canonical_domain": domain,
                "event_family": family,
                "mapping_confidence": confidence,
                **{key: value for key, value in row.items() if key != "name"},
            }
        )
    host_rows = [{"host": row.pop("name"), **row} for row in hosts]
    source_rows = [{"source": row.pop("name"), **row} for row in sources]

    domain_totals: dict[str, dict[str, int]] = defaultdict(lambda: {"event_count": 0, "sourcetype_count": 0})
    for row in sourcetype_rows:
        target = domain_totals[str(row["canonical_domain"])]
        target["event_count"] += int(row["event_count"])
        target["sourcetype_count"] += 1
    domain_rows = [
        {"canonical_domain": name, **values}
        for name, values in sorted(domain_totals.items(), key=lambda item: -item[1]["event_count"])
    ]

    aliases, derived = _parse_props(props)

    _write_csv(telemetry_dir / "bucket_inventory.csv", bucket_rows, list(bucket_rows[0].keys()))
    _write_csv(
        telemetry_dir / "disabled_bucket_inventory.csv", disabled_rows,
        ["bucket", "event_count", "earliest_epoch", "latest_epoch", "earliest_utc", "latest_utc", "reason"],
    )
    _write_csv(
        telemetry_dir / "sourcetype_profile.csv", sourcetype_rows,
        ["sourcetype", "canonical_domain", "event_family", "mapping_confidence", "event_count", "bucket_count",
         "earliest_epoch", "latest_epoch", "earliest_utc", "latest_utc"],
    )
    _write_csv(
        telemetry_dir / "host_profile.csv", host_rows,
        ["host", "event_count", "bucket_count", "earliest_epoch", "latest_epoch", "earliest_utc", "latest_utc"],
    )
    _write_csv(
        telemetry_dir / "source_profile.csv", source_rows,
        ["source", "event_count", "bucket_count", "earliest_epoch", "latest_epoch", "earliest_utc", "latest_utc"],
    )
    _write_csv(telemetry_dir / "domain_profile.csv", domain_rows, ["canonical_domain", "event_count", "sourcetype_count"])
    _write_csv(
        telemetry_dir / "props_field_aliases.csv", aliases,
        ["sourcetype_stanza", "source_field", "alias_field", "config_key"],
    )
    _write_csv(
        telemetry_dir / "props_derived_fields.csv", derived,
        ["sourcetype_stanza", "derived_field", "expression"],
    )

    active_event_count = sum(int(row["event_count"]) for row in bucket_rows)
    sourcetype_event_count = sum(int(row["event_count"]) for row in sourcetype_rows)
    host_event_count = sum(int(row["event_count"]) for row in host_rows)
    source_event_count = sum(int(row["event_count"]) for row in source_rows)
    administrative_events = sum(
        int(row["event_count"]) for row in sourcetype_rows if row["canonical_domain"] == "administrative"
    )
    scenario_rows = [row for row in sourcetype_rows if row["canonical_domain"] != "administrative"]
    scenario_earliest_epoch = min(int(row["earliest_epoch"]) for row in scenario_rows)
    scenario_latest_epoch = max(int(row["latest_epoch"]) for row in scenario_rows)
    summary: dict[str, Any] = {
        "dataset": "BOTS v3",
        "archive_name": source_archive.name,
        "archive_size_bytes": source_archive.stat().st_size,
        **digests,
        "tar_member_count": member_count,
        "file_count": file_count,
        "directory_count": directory_count,
        "uncompressed_file_bytes": uncompressed_bytes,
        "index_name": "botsv3",
        "active_bucket_count": len(bucket_rows),
        "disabled_bucket_count": len(disabled_rows),
        "journal_count": journal_count,
        "manifest_event_count": active_event_count,
        "administrative_event_count": administrative_events,
        "scenario_telemetry_event_count": active_event_count - administrative_events,
        "scenario_earliest_epoch": scenario_earliest_epoch,
        "scenario_latest_epoch": scenario_latest_epoch,
        "scenario_earliest_utc": utc_iso(scenario_earliest_epoch),
        "scenario_latest_utc": utc_iso(scenario_latest_epoch),
        "disabled_bucket_event_count": sum(int(row["event_count"]) for row in disabled_rows),
        "unique_sourcetypes": len(sourcetype_rows),
        "unique_hosts": len(host_rows),
        "unique_sources": len(source_rows),
        "earliest_epoch": min(int(row["earliest_epoch"]) for row in bucket_rows),
        "latest_epoch": max(int(row["latest_epoch"]) for row in bucket_rows),
        "earliest_utc": utc_iso(min(int(row["earliest_epoch"]) for row in bucket_rows)),
        "latest_utc": utc_iso(max(int(row["latest_epoch"]) for row in bucket_rows)),
        "manifest_reconciles_with_sourcetypes": active_event_count == sourcetype_event_count,
        "manifest_reconciles_with_hosts": active_event_count == host_event_count,
        "manifest_reconciles_with_sources": active_event_count == source_event_count,
        "field_alias_count": len(aliases),
        "derived_field_count": len(derived),
        "full_event_export_status": "pending_compatible_splunk_runtime",
    }
    (telemetry_dir / "botsv3_source_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (telemetry_dir / "indexes.conf").write_text(indexes, encoding="utf-8")
    (telemetry_dir / "props.conf").write_text(props, encoding="utf-8")
    (telemetry_dir / "transforms.conf").write_text(transforms, encoding="utf-8")
    (telemetry_dir / "README.txt").write_text(readme, encoding="utf-8")

    export_rows = []
    for row in sourcetype_rows:
        sourcetype = str(row["sourcetype"]).replace('"', '\\"')
        export_rows.append(
            {
                "sourcetype": row["sourcetype"],
                "event_count": row["event_count"],
                "canonical_domain": row["canonical_domain"],
                "field_profile_search": f'index=botsv3 earliest=0 sourcetype="{sourcetype}" | fieldsummary',
                "inventory_search": (
                    f'index=botsv3 earliest=0 sourcetype="{sourcetype}" '
                    '| stats count min(_time) as earliest max(_time) as latest dc(host) as hosts dc(source) as sources'
                ),
            }
        )
    _write_csv(
        telemetry_dir / "splunk_export_plan.csv", export_rows,
        ["sourcetype", "event_count", "canonical_domain", "field_profile_search", "inventory_search"],
    )

    _update_registry(project_root, summary)
    _update_inventory(project_root, summary)

    report = f"""# BOTS v3 Preparation Report

## Source integrity

- Archive: `{source_archive.name}`
- MD5: `{summary['md5']}`
- SHA-256: `{summary['sha256']}`
- Compressed size: {summary['archive_size_bytes']:,} bytes
- Uncompressed file content: {summary['uncompressed_file_bytes']:,} bytes
- Archive members: {summary['tar_member_count']:,}

## Active Splunk index inventory

- Index: `botsv3`
- Active buckets in `.bucketManifest`: {summary['active_bucket_count']:,}
- Disabled/unmanifested buckets: {summary['disabled_bucket_count']:,}
- Raw journal files: {summary['journal_count']:,}
- Active manifest events: {summary['manifest_event_count']:,}
- Scenario telemetry events after excluding administrative content-import metadata: {summary['scenario_telemetry_event_count']:,}
- Primary scenario time range: {summary['scenario_earliest_utc']} to {summary['scenario_latest_utc']}
- Events in disabled bucket directories: {summary['disabled_bucket_event_count']:,}
- Unique sourcetypes: {summary['unique_sourcetypes']:,}
- Unique hosts: {summary['unique_hosts']:,}
- Unique sources: {summary['unique_sources']:,}
- Earliest active event: {summary['earliest_utc']}
- Latest active event: {summary['latest_utc']}

## Reconciliation

- Manifest vs sourcetype totals: **{summary['manifest_reconciles_with_sourcetypes']}**
- Manifest vs host totals: **{summary['manifest_reconciles_with_hosts']}**
- Manifest vs source totals: **{summary['manifest_reconciles_with_sources']}**

The archive contains two active `ess_content_importer` events. They are classified as administrative metadata and excluded from the scenario-telemetry count, while remaining preserved in the source inventory and lineage. One of these events occurs outside the primary 2018 scenario window.

A disabled bucket directory contains two `stream:smtp` events and is not listed in the active bucket manifest. It is recorded separately and is not merged into active dataset totals.

## Generated outputs

- `bucket_inventory.csv`
- `disabled_bucket_inventory.csv`
- `sourcetype_profile.csv`
- `host_profile.csv`
- `source_profile.csv`
- `domain_profile.csv`
- `props_field_aliases.csv`
- `props_derived_fields.csv`
- `splunk_export_plan.csv`
- `botsv3_source_summary.json`

## Processing boundary

BOTS v3 is a pre-indexed Splunk dataset. Bucket metadata, counts, time ranges, hosts, sources, sourcetypes, and app field aliases have been processed directly and reproducibly.

Full event extraction and canonical field normalization remain pending a compatible Splunk runtime. The binary `rawdata/journal.gz` files are not treated as ordinary gzip log files because doing so would bypass Splunk's event boundaries, TSIDX metadata, source typing, and search-time field configuration.
"""
    (report_dir / "BOTSV3_PREPARATION_REPORT.md").write_text(report, encoding="utf-8")

    requirements = """# BOTS v3 Splunk Runtime Requirements

Provide:

- Operating system and version
- Splunk Enterprise version, if already installed
- Deployment type: local, VM, Docker, or remote
- RAM, CPU, and free storage
- Whether required BOTS apps/add-ons may be installed

Do not send passwords or tokens in chat. Credentials must be supplied locally through environment variables or a `.env` file excluded from version control.

## Validation searches

```spl
index=botsv3 earliest=0 | stats count
```

Expected active index count from bucket metadata: `2,030,269` events. The scenario-telemetry count after excluding two administrative content-import events is `2,030,267`.

```spl
index=botsv3 earliest=0 | stats count min(_time) as earliest max(_time) as latest by sourcetype
```

```spl
index=botsv3 earliest=0 | fieldsummary
```

The export stage will run in bounded time windows and per sourcetype, preserving `_time`, `_indextime`, `index`, `host`, `source`, `sourcetype`, `_raw`, and discovered fields.
"""
    (docs_dir / "BOTSV3_SPLUNK_REQUIREMENTS.md").write_text(requirements, encoding="utf-8")
    return summary
