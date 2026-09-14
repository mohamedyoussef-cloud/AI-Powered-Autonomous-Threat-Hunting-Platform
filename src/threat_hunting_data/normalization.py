from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PureWindowsPath
import ipaddress
import re
from typing import Any

from dateutil import parser as dt_parser


def normalize_timestamp(value: Any) -> tuple[str | None, list[str]]:
    """Return a UTC ISO-8601 timestamp and warnings."""
    warnings: list[str] = []
    if value in (None, ""):
        return None, ["missing_timestamp"]
    try:
        dt = dt_parser.parse(str(value))
    except (ValueError, TypeError, OverflowError):
        return None, ["invalid_timestamp"]
    if dt.tzinfo is None:
        warnings.append("timezone_missing_assumed_utc")
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z"), warnings


def strip_balanced_quotes(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def normalize_windows_path(value: str | None) -> tuple[str | None, list[str]]:
    warnings: list[str] = []
    value = strip_balanced_quotes(value)
    if not value:
        return None, warnings
    normalized = value.replace('/', '\\')
    has_unc_prefix = normalized.startswith('\\\\')
    if has_unc_prefix:
        body = re.sub(r'\\+', r'\\', normalized[2:])
        normalized = '\\\\' + body
    else:
        normalized = re.sub(r'\\+', r'\\', normalized)
    return normalized, warnings


def executable_basename(value: str | None) -> str | None:
    normalized, _ = normalize_windows_path(value)
    if not normalized:
        return None
    return PureWindowsPath(normalized).name or None


def normalize_ip(value: Any) -> tuple[str | None, list[str]]:
    if value in (None, "", "-"):
        return None, []
    try:
        return str(ipaddress.ip_address(str(value).strip())), []
    except ValueError:
        return None, ["invalid_ip"]


def split_windows_user(value: str | None) -> dict[str, str | None]:
    result = {"name": None, "domain": None, "original": value}
    if value is None:
        return result
    cleaned = value.strip()
    if not cleaned:
        return result
    if "\\" in cleaned:
        domain, name = cleaned.split("\\", 1)
        result.update(name=name or None, domain=domain or None)
    elif "@" in cleaned:
        name, domain = cleaned.rsplit("@", 1)
        result.update(name=name or None, domain=domain or None)
    else:
        result["name"] = cleaned
    return result
