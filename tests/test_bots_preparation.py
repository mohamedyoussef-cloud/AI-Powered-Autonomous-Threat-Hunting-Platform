from threat_hunting_data.bots_preparation import classify_sourcetype, parse_splunk_metadata_data


def test_parse_splunk_metadata_data() -> None:
    payload = (
        b"0\t2\t10\t100\t200\t210\t\n"
        b"1\tsourcetype::stream:dns\t 7\t100\t180\t200\t\n"
        b"2\tsourcetype::WinEventLog:Security\t 3\t120\t200\t210\t\n"
    )
    summary, rows = parse_splunk_metadata_data(payload, "sourcetype::")
    assert summary["event_count"] == 10
    assert rows[0]["name"] == "stream:dns"
    assert rows[1]["event_count"] == 3


def test_sourcetype_classification() -> None:
    assert classify_sourcetype("stream:dns")[0] == "network"
    assert classify_sourcetype("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")[0] == "endpoint"
    assert classify_sourcetype("ess_content_importer")[0] == "administrative"


def test_protocol_specific_classification_precedes_generic_stream() -> None:
    assert classify_sourcetype("stream:http")[0] == "web"
    assert classify_sourcetype("stream:smtp")[0] == "email"
    assert classify_sourcetype("stream:mysql")[0] == "database"
