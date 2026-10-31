import json

import pytest

from soc_toolkit.alerts import parse_alert
from soc_toolkit.alerts.loader import AlertFormatError, load_alert_data


def test_ndjson_and_concatenated():
    assert load_alert_data('{"a": 1}\n{"b": 2}\n') == [{"a": 1}, {"b": 2}]
    assert load_alert_data('{"a": 1}{"b": 2}') == [{"a": 1}, {"b": 2}]


def test_lenient_json():
    assert load_alert_data('```json\n{"a": [1, 2,],}\n```') == {"a": [1, 2]}
    assert load_alert_data("{'a': True, 'b': None}") == {"a": True, "b": None}
    assert load_alert_data('\ufeff{"a": 1}') == {"a": 1}


def test_cef():
    d = load_alert_data("CEF:0|Kaspersky|KUMA|3.0|1001|Brute force|8|src=45.1.2.3 suser=admin "
                        "cs1=powershell -enc QQBBAA== msg=hello world")
    assert d["name"] == "Brute force" and d["src"] == "45.1.2.3"
    assert d["cs1"] == "powershell -enc QQBBAA==" and d["msg"] == "hello world"


def test_nested_raw_is_expanded():
    raw = 'EventCode=4688 ComputerName=WS1 CommandLine="cmd /c whoami" User=bob'
    d = load_alert_data(json.dumps({"_raw": raw, "ExtendedProperties": '{"x": 1}'}))
    assert d["_raw_parsed"]["CommandLine"] == "cmd /c whoami"
    assert d["ExtendedProperties"] == {"x": 1}


def test_windows_xml_and_text():
    xml = ('<Event><System><EventID>4688</EventID><Computer>WS1</Computer>'
           '<TimeCreated SystemTime="2026-01-01T00:00:00Z"/></System>'
           '<EventData><Data Name="CommandLine">cmd /c whoami</Data></EventData></Event>')
    a = parse_alert(xml)
    assert a.hosts == ["WS1"] and a.commands == ["cmd /c whoami"] and a.event_ids == ["4688"]
    text = ("A new process has been created.\nAccount Name:\tbob\n"
            "New Process Name:\tC:\\Windows\\System32\\cmd.exe\nProcess Command Line:\tcmd /c whoami\n")
    a = parse_alert(text)
    assert a.users == ["bob"] and a.commands == ["cmd /c whoami"]


def test_garbage_raises():
    with pytest.raises(AlertFormatError):
        load_alert_data("просто текст без полей")
    with pytest.raises(json.JSONDecodeError):   # совместимость со старым кодом
        parse_alert("{broken")


def test_wazuh_fields_and_severity(samples):
    a = parse_alert((samples / "alert_wazuh_fp.json").read_text(encoding="utf-8"))
    assert a.source_format == "wazuh" and a.severity == "high"
    assert a.name == "Suspicious PowerShell: execution policy bypass"
    assert a.hosts == ["WS-FIN-022.corp.local"]          # WS-FIN-022 и FQDN склеены
    assert "C:\\Windows\\CCM\\CcmExec.exe" in a.parent_processes


def test_ecs_process_name_is_not_alert_name():
    a = parse_alert(json.dumps({"kibana.alert.rule.name": "Rule X", "process": {"name": "powershell.exe"},
                                "host": {"name": "WS1"}, "@timestamp": "2026-01-01T00:00:00Z"}))
    assert a.name == "Rule X" and a.source_format == "elastic"


def test_sentinel_and_defender(samples):
    s = parse_alert(json.dumps({"AlertName": "Suspicious sign-in", "CompromisedEntity": "user@corp.com",
                                "Entities": '[{"Type": "ip", "Address": "45.1.2.3"}]',
                                "ExtendedProperties": '{"Location": "NL"}', "Severity": "High"}))
    assert s.source_format == "sentinel" and s.name == "Suspicious sign-in" and s.severity == "high"
    d = parse_alert((samples / "alert_defender_blocked.json").read_text(encoding="utf-8"))
    assert d.source_format == "defender" and "Prevented" in d.outcomes and d.users == ["a.smirnova"]
