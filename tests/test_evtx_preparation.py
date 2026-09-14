from __future__ import annotations

import base64

from threat_hunting_data.evtx_preparation import _extract_utf16le_tokens_from_base64, _normalize_endpoint, _normalized_provider


def test_normalize_ipv4_endpoint_with_port() -> None:
    ip, port, warnings = _normalize_endpoint("10.0.2.16:52202")
    assert ip == "10.0.2.16"
    assert port == 52202
    assert warnings == []


def test_normalize_bracketed_endpoint() -> None:
    ip, port, warnings = _normalize_endpoint("[10.0.2.16]:59407")
    assert ip == "10.0.2.16"
    assert port == 59407
    assert warnings == []


def test_channel_repairs_overwritten_sysmon_provider() -> None:
    assert _normalized_provider('"BotFilter82"', "Microsoft-Windows-Sysmon/Operational") == "Microsoft-Windows-Sysmon"


def test_extract_mssql_binary_login_name() -> None:
    payload = base64.b64encode(b"\x18H\x00\x00\x0e\x00\x00\x00\x0c\x00\x00\x00" + "MSEDGEWIN10\x00master\x00".encode("utf-16le")).decode()
    tokens = _extract_utf16le_tokens_from_base64(payload)
    assert tokens[-1] == "master"
