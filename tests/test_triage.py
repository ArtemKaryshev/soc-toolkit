import json

import pytest

from soc_toolkit.alerts import parse_alert
from soc_toolkit.triage import assess, specific_remediation

# файл -> (вердикт, уверенный, эскалация, категория)
EXPECTED = {
    "alert_splunk.json": ("TP", True, True, "malware"),
    "alert_kuma.json": ("TP", True, True, "bruteforce"),
    "alert_phishing.json": ("TP", True, True, "phishing"),
    "alert_defender_blocked.json": ("TP", True, False, "malware"),
    "alert_wazuh_fp.json": ("FP", True, False, None),
}


@pytest.mark.parametrize("name", EXPECTED)
def test_samples(samples, name):
    a = parse_alert((samples / name).read_text(encoding="utf-8"))
    x = assess(a)
    verdict, certain, escalate, category = EXPECTED[name]
    assert (x.verdict, x.certain, x.escalate) == (verdict, certain, escalate), [f.id for f in x.factors]
    if category:
        assert x.category == category
    assert x.escalation_why["ru"] and x.escalation_why["en"]


def alert(**fields):
    return parse_alert(json.dumps({"rule_name": "Test rule", "host": "WS-01", "user": "bob", **fields}))


def test_benign_alert_without_signs_is_fp():
    x = assess(alert(CommandLine="notepad.exe C:\\Users\\bob\\notes.txt"))
    assert x.verdict == "FP" and any(f.id == "nothing" for f in x.factors)


def test_weak_signs_need_review():
    x = assess(alert(CommandLine="cmd.exe /c whoami && ipconfig /all"))
    assert not x.certain and x.escalate
    assert "Данных в алерте недостаточно" in x.escalation_why["ru"]


def test_siem_disposition_wins():
    x = assess(alert(CommandLine="powershell -enc " + "A" * 40, classification="FalsePositive"))
    assert x.verdict == "FP" and x.confidence == 95


def test_reputation_changes_verdict():
    a = alert(dest_ip="91.215.85.10", url="http://91.215.85.10/a")
    assert assess(a).verdict == "FP"
    assert assess(a, {"91.215.85.10": "malicious"}).verdict == "TP"


def test_clean_reputation_lowers_score():
    a = alert(CommandLine="powershell -nop -w hidden", dest_ip="8.8.8.8")
    assert assess(a, {"8.8.8.8": "clean"}).score < assess(a).score


def test_failed_bruteforce_not_escalated():
    events = [{"EventID": 4625, "IpAddress": "45.1.2.3", "TimeCreated": f"2026-01-01T00:00:{i:02d}Z"}
              for i in range(12)]
    x = assess(parse_alert(json.dumps({"rule_name": "Brute force", "host": "SRV-01", "user": "admin",
                                       "events": events})))
    assert x.verdict == "TP" and x.category == "bruteforce" and x.outcome == "blocked"
    assert not x.escalate and "Эскалация не требуется" in x.escalation_why["ru"]


def test_ransomware_always_escalated():
    x = assess(alert(CommandLine="vssadmin.exe delete shadows /all /quiet", action="blocked"))
    assert x.category == "ransomware" and x.escalate


def test_executed_despite_detection_is_escalated():
    x = assess(alert(CommandLine="powershell -enc " + "QQBBAA" * 8, action="Quarantined",
                     ParentImage="C:\\Program Files\\Microsoft Office\\WINWORD.EXE"))
    assert x.escalate and "успел выполниться" in x.escalation_why["ru"]


def test_matched_fragment_in_text():
    x = assess(alert(ParentImage="C:\\Windows\\CCM\\CcmExec.exe", Image="powershell.exe"))
    mgmt = next(f for f in x.factors if f.id == "mgmt_tool")
    assert "C:\\Windows\\CCM\\CcmExec.exe" in mgmt.ru


def test_specific_remediation_names_entities(samples):
    a = parse_alert((samples / "alert_kuma.json").read_text(encoding="utf-8"))
    rem = " ".join(specific_remediation(a, assess(a)))
    assert "45[.]155[.]205[.]233" in rem and "admin" in rem and "SRV-RDP-01" in rem
