from __future__ import annotations

import re
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from Evtx.Evtx import Evtx


EVTX_REPO_RAW = (
    "https://raw.githubusercontent.com/"
    "sbousseaden/EVTX-ATTACK-SAMPLES/master/"
)

EVENT_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def _download_evtx(path: str, destination: Path) -> None:
    url = EVTX_REPO_RAW + urllib.parse.quote(path, safe="/")
    urllib.request.urlretrieve(url, destination)


def _event_id(root: ET.Element) -> str:
    node = root.find("e:System/e:EventID", EVENT_NS)
    return (node.text or "").strip() if node is not None else ""


def _system_value(root: ET.Element, name: str) -> str:
    node = root.find(f"e:System/e:{name}", EVENT_NS)
    if node is None:
        return ""

    if name == "TimeCreated":
        return node.attrib.get("SystemTime", "")

    return (node.text or "").strip()


def _event_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}

    node = root.find("e:EventData", EVENT_NS)
    if node is None:
        return data

    for item in node:
        name = item.attrib.get("Name", "")
        if name:
            data[name] = item.text or ""

    return data


def normalize_sysmon_process_event(
    xml: str,
    source_path: str,
) -> dict[str, Any] | None:
    """
    Convert Sysmon Event ID 1 into normalized process telemetry.

    This function does NOT create a finding.
    It only represents telemetry extracted from an EVTX event.
    """

    root = ET.fromstring(xml)

    if _event_id(root) != "1":
        return None

    data = _event_data(root)

    return {
        "event_id": "1",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": _system_value(root, "Channel"),
        "timestamp": _system_value(root, "TimeCreated"),
        "host": _system_value(root, "Computer"),
        "user": data.get("User", ""),
        "image": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "process_id": data.get("ProcessId", ""),
        "process_guid": data.get("ProcessGuid", ""),
        "parent_image": data.get("ParentImage", ""),
        "parent_command_line": data.get("ParentCommandLine", ""),
        "rule_name": data.get("RuleName", ""),
        "source_dataset": "evtx",
        "source_path": source_path,
    }


def matches_powershell_encoded_command(
    telemetry: dict[str, Any],
) -> bool:
    """
    Match the current Campaign template rule:

        Image endswith powershell.exe
        AND
        CommandLine contains -enc

    This is a deterministic matcher for the current template_v0 rule.
    """

    image = str(telemetry.get("image") or "").lower()
    command_line = str(telemetry.get("command_line") or "").lower()

    image_match = image.endswith("\\powershell.exe")

    encoded_match = bool(
        re.search(r"[-/]\s*enc(odedcommand)?\b", command_line)
    )

    return image_match and encoded_match


def hunt_evtx_sample(
    source_path: str,
    matcher: str = "powershell_encoded_command",
) -> dict[str, Any]:
    """
    Download one public EVTX sample to a temporary file, parse it,
    normalize Sysmon process events, and apply a deterministic matcher.

    The raw EVTX file is deleted before returning.
    """

    tmp = Path(tempfile.gettempdir()) / "threathunt_evtx_runtime.evtx"

    telemetry_count = 0
    matches: list[dict[str, Any]] = []

    try:
        _download_evtx(source_path, tmp)

        with Evtx(str(tmp)) as log:
            for record in log.records():
                telemetry = normalize_sysmon_process_event(
                    record.xml(),
                    source_path,
                )

                if telemetry is None:
                    continue

                telemetry_count += 1

                if matcher == "powershell_encoded_command":
                    if matches_powershell_encoded_command(telemetry):
                        matches.append(telemetry)

        return {
            "source_dataset": "evtx",
            "source_path": source_path,
            "telemetry_events": telemetry_count,
            "matched_events": len(matches),
            "matches": matches,
            "matcher": matcher,
        }

    finally:
        if tmp.exists():
            tmp.unlink()


def evtx_match_to_finding(
    match: dict,
    *,
    rule_id: str,
    rule_title: str,
    technique_id: str = "T1059.001",
) -> dict:
    """
    Convert one real EVTX detection match into the canonical HuntFinding shape.

    This does not claim that the ATT&CK technique occurred in a client
    environment. It records that the detection rule matched telemetry
    contained in the supplied EVTX sample.
    """
    import hashlib
    import json

    event_id = str(match.get("event_id", ""))
    host = str(match.get("host", ""))
    user = str(match.get("user", ""))
    timestamp = str(match.get("timestamp", ""))
    image = str(match.get("image", ""))
    command_line = str(match.get("command_line", ""))
    source_path = str(match.get("source_path", ""))

    stable_material = "|".join([
        "evtx",
        source_path,
        event_id,
        timestamp,
        host,
        image,
        command_line,
    ])

    digest = hashlib.sha256(stable_material.encode("utf-8")).hexdigest()[:20]

    finding_id = f"EVTX-{digest}"
    case_id = f"EVTX-CASE-{digest[:12]}"

    return {
        "finding_id": finding_id,
        "case_id": case_id,
        "rule_id": rule_id,
        "rule_title": rule_title,
        "compiled_query": (
            "Image endswith \\\\powershell.exe AND "
            "CommandLine contains -enc"
        ),
        "event_references": json.dumps(
            [{
                "event_id": event_id,
                "source_path": source_path,
                "timestamp": timestamp,
            }],
            ensure_ascii=False,
        ),
        "time_start": timestamp,
        "time_end": timestamp,
        "hosts": host,
        "users": user,
        "processes": json.dumps(
            [{
                "image": image,
                "command_line": command_line,
                "process_id": str(match.get("process_id", "")),
                "process_guid": str(match.get("process_guid", "")),
                "parent_image": str(match.get("parent_image", "")),
                "parent_command_line": str(
                    match.get("parent_command_line", "")
                ),
            }],
            ensure_ascii=False,
        ),
        "ips": "",
        "attack_technique_ids": technique_id,
        "narrative": (
            "Detection rule matched a PowerShell encoded-command event "
            "in the supplied EVTX telemetry sample. "
            "This is sample telemetry evidence and does not by itself "
            "establish technique occurrence in a client environment."
        ),
        "risk_score": 85.0,
        "threat_probability": None,
        "label": "suspicious",
        "verification_status": "unverified",
        "source_dataset": "evtx",
    }
