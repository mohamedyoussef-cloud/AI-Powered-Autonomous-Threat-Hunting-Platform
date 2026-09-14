from __future__ import annotations

from dataclasses import dataclass
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path, PureWindowsPath
import re
import subprocess
from typing import Any, Iterable

import pandas as pd
import yaml

from .normalization import executable_basename, normalize_ip, normalize_windows_path, split_windows_user


TECHNIQUE_RE = re.compile(r"(?i)(?<![A-Z0-9])T(\d{4})(?:[._-](\d{3}))?(?!\d)")


@dataclass(frozen=True)
class EvtxPreparationPaths:
    source_root: Path
    project_root: Path

    @property
    def source_csv(self) -> Path:
        return self.source_root / "evtx_data.csv"

    @property
    def telemetry_dir(self) -> Path:
        return self.project_root / "data" / "processed" / "telemetry"

    @property
    def interim_dir(self) -> Path:
        return self.project_root / "data" / "interim" / "evtx_parsed"

    @property
    def report_dir(self) -> Path:
        return self.project_root / "reports"


def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    try:
        return bool(pd.isna(value))
    except (TypeError, ValueError):
        return False


def _python_value(value: Any) -> Any:
    if _is_missing(value):
        return None
    if hasattr(value, "item"):
        try:
            value = value.item()
        except ValueError:
            pass
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def first_non_empty(row: pd.Series, candidates: Iterable[str]) -> tuple[Any, str | None]:
    for field in candidates:
        if field not in row.index:
            continue
        value = row[field]
        if _is_missing(value):
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return _python_value(value), field
    return None, None


def _safe_int(value: Any) -> int | None:
    if _is_missing(value):
        return None
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except (ValueError, TypeError, OverflowError):
        return None


def _timestamp_utc(value: Any) -> tuple[str | None, list[str]]:
    if _is_missing(value):
        return None, ["missing_timestamp"]
    dt = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(dt):
        return None, ["invalid_timestamp"]
    return dt.isoformat().replace("+00:00", "Z"), []


def _normalize_endpoint(value: Any) -> tuple[str | None, int | None, list[str]]:
    if _is_missing(value):
        return None, None, []
    text = str(value).strip()
    host = text
    port: int | None = None
    if text.startswith("[") and "]:" in text:
        host, port_text = text[1:].split("]:", 1)
        port = _safe_int(port_text)
    elif text.count(":") == 1:
        candidate_host, candidate_port = text.rsplit(":", 1)
        if _safe_int(candidate_port) is not None:
            host = candidate_host
            port = _safe_int(candidate_port)
    normalized, warnings = normalize_ip(host)
    return normalized, port, warnings


def _hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_techniques(*values: Any, valid_ids: set[str] | None = None) -> list[str]:
    found: set[str] = set()
    for value in values:
        if _is_missing(value):
            continue
        for match in TECHNIQUE_RE.finditer(str(value)):
            technique = f"T{match.group(1)}"
            if match.group(2):
                technique += f".{match.group(2)}"
            if valid_ids is None or technique in valid_ids:
                found.add(technique)
    return sorted(found)


def _extract_utf16le_tokens_from_base64(value: Any) -> list[str]:
    if _is_missing(value):
        return []
    try:
        decoded = base64.b64decode(str(value), validate=True)
    except (ValueError, TypeError):
        return []
    text = decoded.decode("utf-16le", errors="ignore")
    tokens = re.findall(r"[A-Za-z0-9_.@$-]{2,}", text)
    return tokens


def _parse_hashes(value: Any) -> dict[str, str]:
    if _is_missing(value):
        return {}
    result: dict[str, str] = {}
    for token in re.split(r"[,;]", str(value)):
        if "=" not in token:
            continue
        key, val = token.split("=", 1)
        key = key.strip().lower().replace("-", "")
        val = val.strip()
        if key and val and val != "-":
            result[key] = val
    return result


def _normalized_provider(provider: str | None, channel: str | None) -> str | None:
    # The repository CSV can overwrite Provider.Name with EventData.Name.
    # Channel is authoritative for the providers below.
    channel_map = {
        "Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon",
        "Microsoft-Windows-PowerShell/Operational": "Microsoft-Windows-PowerShell",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
        "Microsoft-Windows-Bits-Client/Operational": "Microsoft-Windows-Bits-Client",
        "Microsoft-Windows-WinRM/Operational": "Microsoft-Windows-WinRM",
    }
    return channel_map.get(channel or "", provider)


def _event_mapping(provider: str | None, channel: str | None, event_id: str, mapping: dict[str, Any]) -> dict[str, Any]:
    providers = mapping.get("providers", {})
    provider_rule = providers.get(provider or "")
    if provider_rule:
        event_rule = provider_rule.get("event_ids", {}).get(str(event_id))
        if event_rule:
            return dict(event_rule)
        if provider_rule.get("default"):
            return dict(provider_rule["default"])
    channel_rule = mapping.get("channel_fallbacks", {}).get(channel or "")
    if channel_rule:
        return dict(channel_rule)
    return dict(mapping.get("default", {"category": "other", "action": "windows_event"}))


def _file_tactic(relative_path: str) -> str | None:
    parts = Path(relative_path).parts
    if len(parts) < 2:
        return None
    return parts[0]


def build_file_inventory(source_root: Path, parsed_df: pd.DataFrame) -> pd.DataFrame:
    event_counts = parsed_df.groupby(["EVTX_Tactic", "EVTX_FileName"], dropna=False).size().to_dict()
    records: list[dict[str, Any]] = []
    for path in sorted(source_root.rglob("*.evtx")):
        relative = path.relative_to(source_root).as_posix()
        tactic = _file_tactic(relative)
        key = (tactic, path.name)
        event_count = int(event_counts.get(key, 0))
        records.append(
            {
                "relative_path": relative,
                "file_name": path.name,
                "tactic_from_path": tactic,
                "size_bytes": path.stat().st_size,
                "sha256": _hash_file(path),
                "parsed_in_published_csv": event_count > 0,
                "published_csv_event_count": event_count,
                "explicit_technique_ids": "|".join(_extract_techniques(path.name)),
            }
        )
    return pd.DataFrame.from_records(records)


def _path_lookup(file_inventory: pd.DataFrame) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for row in file_inventory.itertuples(index=False):
        tactic = row.tactic_from_path
        if tactic:
            result[(str(tactic), str(row.file_name))] = str(row.relative_path)
    return result


def _canonical_event(
    row: pd.Series,
    row_index: int,
    source_path: str,
    event_mapping: dict[str, Any],
    field_mapping: dict[str, Any],
    valid_techniques: set[str],
    ingested_at: str,
) -> dict[str, Any]:
    fields = field_mapping["canonical_fields"]

    timestamp_raw, timestamp_field = first_non_empty(row, fields["timestamp"]["candidates"])
    timestamp, warnings = _timestamp_utc(timestamp_raw)

    event_id_raw, event_id_field = first_non_empty(row, fields["event.id"]["candidates"])
    event_id_int = _safe_int(event_id_raw)
    event_id = str(event_id_int if event_id_int is not None else event_id_raw)

    provider, provider_field = first_non_empty(row, fields["event.provider"]["candidates"])
    channel, channel_field = first_non_empty(row, fields["event.channel"]["candidates"])
    provider = str(provider) if provider is not None else None
    channel = str(channel) if channel is not None else None
    provider_normalized = _normalized_provider(provider, channel)
    mapped = _event_mapping(provider_normalized, channel, event_id, event_mapping)

    host_name, host_field = first_non_empty(row, fields["host.name"]["candidates"])
    combined_user, user_field = first_non_empty(row, fields["user.combined"]["candidates"])
    domain, domain_field = first_non_empty(row, fields["user.domain"]["candidates"])
    user_id, user_id_field = first_non_empty(row, fields["user.id"]["candidates"])
    user_parts = split_windows_user(str(combined_user) if combined_user is not None else None)
    if domain and not user_parts.get("domain"):
        user_parts["domain"] = str(domain)

    # Event 1149 stores username/domain/source IP in namespaced Param1/2/3 fields.
    if provider_normalized == "Microsoft-Windows-TerminalServices-RemoteConnectionManager" and event_id == "1149":
        rdp_user = row.get("{Event_NS}Param1")
        rdp_domain = row.get("{Event_NS}Param2")
        rdp_source = row.get("{Event_NS}Param3")
        if not _is_missing(rdp_user):
            user_parts["name"] = str(rdp_user)
            user_field = "{Event_NS}Param1"
        if not _is_missing(rdp_domain):
            user_parts["domain"] = str(rdp_domain)
            domain_field = "{Event_NS}Param2"
        if not _is_missing(rdp_source):
            # Applied below if no regular source IP field is present.
            row = row.copy()
            row["ClientIP"] = rdp_source

    # SQL Server 18456 stores computer/login strings inside the Binary payload.
    if provider_normalized == "MSSQLSERVER" and event_id == "18456" and not user_parts.get("name"):
        binary_tokens = _extract_utf16le_tokens_from_base64(row.get("Binary"))
        if binary_tokens:
            user_parts["name"] = binary_tokens[-1]
            user_field = "Binary:utf16le:last_token"

    executable_raw, executable_field = first_non_empty(row, fields["process.executable"]["candidates"])
    executable, path_warnings = normalize_windows_path(str(executable_raw) if executable_raw is not None else None)
    warnings.extend(path_warnings)
    command_line, command_line_field = first_non_empty(row, fields["process.command_line"]["candidates"])
    pid_raw, pid_field = first_non_empty(row, fields["process.pid"]["candidates"])

    parent_raw, parent_field = first_non_empty(row, fields["process.parent.executable"]["candidates"])
    parent_executable, parent_path_warnings = normalize_windows_path(str(parent_raw) if parent_raw is not None else None)
    warnings.extend(parent_path_warnings)
    parent_command_line, parent_command_line_field = first_non_empty(row, fields["process.parent.command_line"]["candidates"])
    parent_pid_raw, parent_pid_field = first_non_empty(row, fields["process.parent.pid"]["candidates"])

    source_ip_raw, source_ip_field = first_non_empty(row, fields["source.ip"]["candidates"])
    source_ip, embedded_source_port, source_ip_warnings = _normalize_endpoint(source_ip_raw)
    warnings.extend(source_ip_warnings)
    source_port_raw, source_port_field = first_non_empty(row, fields["source.port"]["candidates"])

    destination_ip_raw, destination_ip_field = first_non_empty(row, fields["destination.ip"]["candidates"])
    destination_ip, embedded_destination_port, destination_ip_warnings = _normalize_endpoint(destination_ip_raw)
    warnings.extend(destination_ip_warnings)
    destination_port_raw, destination_port_field = first_non_empty(row, fields["destination.port"]["candidates"])

    file_path_raw, file_path_field = first_non_empty(row, fields["file.path"]["candidates"])
    file_path, file_path_warnings = normalize_windows_path(str(file_path_raw) if file_path_raw is not None else None)
    warnings.extend(file_path_warnings)

    registry_path_raw, registry_path_field = first_non_empty(row, fields["registry.path"]["candidates"])
    registry_path, registry_path_warnings = normalize_windows_path(str(registry_path_raw) if registry_path_raw is not None else None)
    warnings.extend(registry_path_warnings)
    registry_data, registry_data_field = first_non_empty(row, fields["registry.data"]["candidates"])

    record_id = _safe_int(row.get("EventRecordID"))
    source_record_id = f"{source_path}::{record_id if record_id is not None else row_index}::{row_index}"
    event_uid = hashlib.sha256(f"EVTX_ATTACK_SAMPLES|{source_record_id}".encode("utf-8")).hexdigest()

    technique_ids = _extract_techniques(row.get("EVTX_FileName"), row.get("RuleName"), valid_ids=valid_techniques)
    tactic = None if _is_missing(row.get("EVTX_Tactic")) else str(row.get("EVTX_Tactic"))

    raw = {str(key): _python_value(value) for key, value in row.items() if key != "Unnamed: 0" and not _is_missing(value)}

    selected_fields = {
        "timestamp": timestamp_field,
        "event.id": event_id_field,
        "event.provider": provider_field,
        "event.channel": channel_field,
        "host.name": host_field,
        "user.name": user_field,
        "user.domain": domain_field,
        "user.id": user_id_field,
        "process.executable": executable_field,
        "process.command_line": command_line_field,
        "process.pid": pid_field,
        "process.parent.executable": parent_field,
        "process.parent.command_line": parent_command_line_field,
        "process.parent.pid": parent_pid_field,
        "source.ip": source_ip_field,
        "source.port": source_port_field,
        "destination.ip": destination_ip_field,
        "destination.port": destination_port_field,
        "file.path": file_path_field,
        "registry.path": registry_path_field,
        "registry.data": registry_data_field,
    }

    missing_required: list[str] = []
    for field_name, field_value in (("timestamp", timestamp), ("event.id", event_id), ("host.name", host_name)):
        if field_value in (None, "", "None", "nan"):
            missing_required.append(field_name)

    category = mapped.get("category", "other")
    if category == "process" and mapped.get("action") == "process_creation" and not executable:
        warnings.append("process_creation_missing_executable")
    if category == "network" and not any((source_ip, destination_ip, row.get("ShareName"))):
        warnings.append("network_event_missing_ip_or_share")
    if category == "authentication" and not user_parts.get("name"):
        warnings.append("authentication_event_missing_user")
    if source_path.startswith("UNRESOLVED/"):
        warnings.append("source_file_path_unresolved")

    warnings = sorted(set(warnings))
    quality_score = max(0.0, 1.0 - 0.2 * len(missing_required) - 0.04 * len(warnings))

    return {
        "event_uid": event_uid,
        "timestamp": timestamp,
        "event": {
            "id": event_id,
            "category": category,
            "action": mapped.get("action", "windows_event"),
            "provider": provider,
            "provider_normalized": provider_normalized,
            "channel": channel,
            "dataset": "evtx_attack_samples",
            "outcome": mapped.get("outcome"),
        },
        "host": {"id": None, "name": str(host_name) if host_name is not None else None, "ip": []},
        "user": {
            "id": str(user_id) if user_id is not None else None,
            "name": user_parts.get("name"),
            "domain": user_parts.get("domain"),
            "privilege_level": None,
        },
        "process": {
            "entity_id": None,
            "name": executable_basename(executable),
            "executable": executable,
            "command_line": str(command_line) if command_line is not None else None,
            "pid": _safe_int(pid_raw) if _safe_int(pid_raw) is not None else (_python_value(pid_raw) if pid_raw is not None else None),
            "parent": {
                "name": executable_basename(parent_executable),
                "executable": parent_executable,
                "pid": _safe_int(parent_pid_raw) if _safe_int(parent_pid_raw) is not None else (_python_value(parent_pid_raw) if parent_pid_raw is not None else None),
                "command_line": str(parent_command_line) if parent_command_line is not None else None,
            },
        },
        "source": {"ip": source_ip, "port": _safe_int(source_port_raw) if _safe_int(source_port_raw) is not None else embedded_source_port},
        "destination": {"ip": destination_ip, "port": _safe_int(destination_port_raw) if _safe_int(destination_port_raw) is not None else embedded_destination_port},
        "file": {
            "name": PureWindowsPath(file_path).name if file_path else None,
            "path": file_path,
            "size": _safe_int(row.get("fileLength")),
            "hashes": _parse_hashes(row.get("Hashes") if not _is_missing(row.get("Hashes")) else row.get("Hash")),
        },
        "registry": {
            "path": registry_path,
            "key": None,
            "value": None,
            "data": _python_value(registry_data),
        },
        "cloud": {"provider": None, "account_id": None, "region": None, "service": None, "operation": None, "resource_id": None},
        "attack": {
            "technique_ids": technique_ids,
            "tactics": [tactic] if tactic else [],
            "mapping_source": "explicit_filename_or_rule_tag" if technique_ids else "tactic_folder_only",
        },
        "data_quality": {
            "missing_required_fields": missing_required,
            "mapping_warnings": warnings,
            "quality_score": round(quality_score, 4),
            "selected_source_fields": {k: v for k, v in selected_fields.items() if v},
        },
        "raw": raw,
        "lineage": {
            "source_dataset": "EVTX_ATTACK_SAMPLES",
            "source_record_id": source_record_id,
            "schema_version": "1.0.0",
            "pipeline_version": "0.3.0",
            "source_file": source_path,
            "ingested_at": ingested_at,
        },
    }


def prepare_evtx_dataset(source_root: Path, project_root: Path, source_archive: Path | None = None) -> dict[str, Any]:
    paths = EvtxPreparationPaths(source_root=source_root, project_root=project_root)
    paths.telemetry_dir.mkdir(parents=True, exist_ok=True)
    paths.interim_dir.mkdir(parents=True, exist_ok=True)
    paths.report_dir.mkdir(parents=True, exist_ok=True)

    if not paths.source_csv.exists():
        raise FileNotFoundError(f"Published parsed CSV not found: {paths.source_csv}")

    df = pd.read_csv(paths.source_csv, low_memory=False)
    field_mapping = yaml.safe_load((project_root / "mappings" / "evtx_samples_csv_field_mapping.yaml").read_text(encoding="utf-8"))
    event_mapping = yaml.safe_load((project_root / "configs" / "evtx_event_mapping.yaml").read_text(encoding="utf-8"))

    valid_techniques: set[str] = set()
    active_path = project_root / "data" / "processed" / "knowledge" / "attack_techniques_active.jsonl"
    if active_path.exists():
        with active_path.open(encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                technique = record.get("technique_id")
                if technique:
                    valid_techniques.add(str(technique))

    file_inventory = build_file_inventory(source_root, df)
    path_lookup = _path_lookup(file_inventory)
    ingested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    canonical_path = paths.telemetry_dir / "evtx_canonical_events.jsonl.gz"
    flat_records: list[dict[str, Any]] = []
    warning_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    unresolved_paths = 0

    with gzip.open(canonical_path, "wt", encoding="utf-8") as output:
        for idx, row in df.iterrows():
            tactic = str(row.get("EVTX_Tactic"))
            filename = str(row.get("EVTX_FileName"))
            source_path = path_lookup.get((tactic, filename), f"UNRESOLVED/{tactic}/{filename}")
            if source_path.startswith("UNRESOLVED/"):
                unresolved_paths += 1
            event = _canonical_event(row, idx, source_path, event_mapping, field_mapping, valid_techniques, ingested_at)
            output.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

            category = event["event"]["category"]
            action = event["event"]["action"]
            category_counts[category] = category_counts.get(category, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1
            for warning in event["data_quality"]["mapping_warnings"]:
                warning_counts[warning] = warning_counts.get(warning, 0) + 1

            flat_records.append(
                {
                    "event_uid": event["event_uid"],
                    "timestamp": event["timestamp"],
                    "event_id": event["event"]["id"],
                    "event_category": category,
                    "event_action": action,
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
                    "attack_tactics": "|".join(event["attack"].get("tactics", [])),
                    "attack_technique_ids": "|".join(event["attack"].get("technique_ids", [])),
                    "source_file": event["lineage"]["source_file"],
                    "quality_score": event["data_quality"]["quality_score"],
                    "mapping_warnings": "|".join(event["data_quality"]["mapping_warnings"]),
                }
            )

    flat_df = pd.DataFrame.from_records(flat_records)
    flat_df.to_csv(paths.telemetry_dir / "evtx_canonical_events_flat.csv.gz", index=False, compression="gzip")
    df.to_csv(paths.interim_dir / "evtx_data_source_native.csv.gz", index=False, compression="gzip")

    file_inventory.to_csv(paths.telemetry_dir / "evtx_source_file_inventory.csv", index=False)
    file_inventory.loc[~file_inventory["parsed_in_published_csv"]].to_csv(paths.telemetry_dir / "evtx_unparsed_files.csv", index=False)

    field_profile = pd.DataFrame(
        {
            "source_field": df.columns,
            "non_null_count": [int(df[c].notna().sum()) for c in df.columns],
            "coverage_ratio": [round(float(df[c].notna().mean()), 6) for c in df.columns],
            "unique_count": [int(df[c].nunique(dropna=True)) for c in df.columns],
            "pandas_dtype": [str(df[c].dtype) for c in df.columns],
        }
    ).sort_values(["non_null_count", "source_field"], ascending=[False, True])
    field_profile.to_csv(paths.telemetry_dir / "evtx_field_profile.csv", index=False)

    profile_rows: list[dict[str, Any]] = []
    for (provider, channel, event_id), group in df.groupby(["ProviderName", "Channel", "EventID"], dropna=False):
        event_id_text = str(_safe_int(event_id) if _safe_int(event_id) is not None else event_id)
        provider_normalized = _normalized_provider(str(provider), str(channel))
        mapped = _event_mapping(provider_normalized, str(channel), event_id_text, event_mapping)
        profile_rows.append(
            {
                "provider": provider,
                "provider_normalized": provider_normalized,
                "channel": channel,
                "event_id": event_id_text,
                "event_count": len(group),
                "unique_files": int(group["EVTX_FileName"].nunique()),
                "canonical_category": mapped.get("category"),
                "canonical_action": mapped.get("action"),
            }
        )
    pd.DataFrame(profile_rows).sort_values("event_count", ascending=False).to_csv(paths.telemetry_dir / "evtx_event_id_profile.csv", index=False)

    tactic_profile = (
        df.groupby("EVTX_Tactic", dropna=False)
        .agg(event_count=("EventID", "size"), unique_files=("EVTX_FileName", "nunique"), unique_event_ids=("EventID", "nunique"), unique_channels=("Channel", "nunique"))
        .reset_index()
        .sort_values("event_count", ascending=False)
    )
    tactic_profile.to_csv(paths.telemetry_dir / "evtx_tactic_profile.csv", index=False)

    try:
        source_commit = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        source_commit = None
    archive_sha256 = _hash_file(source_archive) if source_archive and source_archive.exists() else None

    summary = {
        "pipeline_version": "0.3.0",
        "source_repository_commit": source_commit,
        "source_archive_sha256": archive_sha256,
        "raw_evtx_file_count": int(len(file_inventory)),
        "raw_evtx_size_bytes": int(file_inventory["size_bytes"].sum()),
        "published_csv_rows": int(len(df)),
        "published_csv_columns": int(len(df.columns)),
        "published_csv_unique_files": int(df["EVTX_FileName"].nunique()),
        "raw_files_covered_by_published_csv": int(file_inventory["parsed_in_published_csv"].sum()),
        "raw_files_not_covered_by_published_csv": int((~file_inventory["parsed_in_published_csv"]).sum()),
        "canonical_event_count": int(len(flat_df)),
        "canonical_event_category_counts": dict(sorted(category_counts.items())),
        "canonical_event_action_counts": dict(sorted(action_counts.items(), key=lambda item: (-item[1], item[0]))),
        "mapping_warning_counts": dict(sorted(warning_counts.items(), key=lambda item: (-item[1], item[0]))),
        "unresolved_csv_source_paths": int(unresolved_paths),
        "timestamp_min_utc": flat_df["timestamp"].min(),
        "timestamp_max_utc": flat_df["timestamp"].max(),
        "mean_quality_score": round(float(flat_df["quality_score"].mean()), 6),
        "explicit_technique_mapped_event_count": int((flat_df["attack_technique_ids"].fillna("") != "").sum()),
        "notes": [
            "The repository-provided evtx_data.csv is used as the source-native parsed event table.",
            "Raw EVTX files not represented in the published CSV are inventoried but no synthetic events are created for them.",
            "EVTX_Tactic is preserved as a source label; ATT&CK technique IDs are only accepted when explicitly present in a filename or rule field and valid in ATT&CK v19.1.",
        ],
    }
    (paths.telemetry_dir / "evtx_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    return summary
