from threat_hunting_data.normalization import (
    executable_basename,
    normalize_ip,
    normalize_timestamp,
    normalize_windows_path,
    split_windows_user,
)


def test_timestamp_to_utc():
    value, warnings = normalize_timestamp("2026-08-05T11:00:00+03:00")
    assert value == "2026-08-05T08:00:00Z"
    assert warnings == []


def test_windows_path_and_basename():
    value, warnings = normalize_windows_path('"C:/Windows/System32/cmd.exe"')
    assert value == r"C:\Windows\System32\cmd.exe"
    assert warnings == []
    assert executable_basename(value) == "cmd.exe"


def test_ip_validation():
    assert normalize_ip("10.0.0.1") == ("10.0.0.1", [])
    assert normalize_ip("not-an-ip")[0] is None


def test_user_parsing():
    parsed = split_windows_user(r"LAB\alice")
    assert parsed["domain"] == "LAB"
    assert parsed["name"] == "alice"


def test_normalize_unc_path() -> None:
    normalized, warnings = normalize_windows_path(r"\\server\share\folder\file.exe")
    assert normalized == r"\\server\share\folder\file.exe"
    assert warnings == []
