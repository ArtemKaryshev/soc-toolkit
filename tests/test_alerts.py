import json

import pytest

from soc_toolkit.alerts import parse_alert
from soc_toolkit.alerts.parser import detect_format, normalize_severity


def test_splunk_alert(samples):
    a = parse_alert((samples / "alert_splunk.json").read_text(encoding="utf-8"))
    assert a.name == "Suspicious Encoded PowerShell Execution"
    assert a.severity == "high" and a.source_format == "splunk"
    assert a.hosts == ["WS-ACC-017"]
    assert a.src_ips == ["10.10.20.17"] and a.dest_ips == ["185.220.101.45"]
    assert any("-enc" in c for c in a.commands)
    assert {m.technique for m in a.mitre} >= {"T1059.001", "T1566.001", "T1204.002"}
    assert next(m for m in a.mitre if m.technique == "T1059.001").explicit


def test_kuma_alert_with_nested_events(samples):
    a = parse_alert((samples / "alert_kuma.json").read_text(encoding="utf-8"))
    assert a.source_format == "kuma"
    assert a.name.startswith("[R] Brute force")
    assert a.hosts == ["SRV-RDP-01"] and a.users == ["admin"]
    assert a.event_ids == ["4625", "4624"]
    assert len(a.timeline) == 9 and "4625" in a.timeline[0].summary and "4624" in a.timeline[-1].summary
    assert a.first_seen == "2026-10-28T09:10:00Z" and a.last_seen == "2026-10-28T09:18:44Z"
    assert "T1110" in {m.technique for m in a.mitre}


def test_elastic_ecs_dotted_paths():
    alert = {"@timestamp": "2026-10-28T10:00:00Z", "rule": {"name": "Mimikatz"}, "host": {"name": "pc1"},
             "source": {"ip": "8.8.8.8"}, "process": {"command_line": "mimikatz.exe sekurlsa::logonpasswords"}}
    a = parse_alert(alert)
    assert a.source_format == "elastic"
    assert a.hosts == ["pc1"] and a.src_ips == ["8.8.8.8"]
    assert "T1003" in {m.technique for m in a.mitre}


def test_list_of_events_and_ip_in_host_field():
    a = parse_alert([{"time": "2026-01-01T00:00:00", "host": "10.1.1.1"},
                     {"time": "2026-01-01T00:01:00", "host": "pc"}])
    assert a.hosts == ["pc"] and "10.1.1.1" in a.dest_ips
    assert len(a.timeline) == 2


def test_query_params(samples):
    a = parse_alert((samples / "alert_splunk.json").read_text(encoding="utf-8"))
    p = a.query_params()
    assert p["user"] == "ivan.petrov" and p["host"] == "WS-ACC-017"
    assert p["ip"] == "185.220.101.45" and p["process"] == "powershell.exe"


def test_invalid_json():
    with pytest.raises(json.JSONDecodeError):
        parse_alert("{not json")


@pytest.mark.parametrize("raw, expected", [("High", "high"), ("8", "high"), ("95", "critical"), ("3", "low"),
                                           ("средний", "medium"), ("weird", "weird")])
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


def test_detect_format_generic():
    assert detect_format({"foo", "bar"}) == "generic"
