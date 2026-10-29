import pytest

from soc_toolkit.alerts import parse_alert
from soc_toolkit.reports import ReportInput, draft_escalation, draft_reason, render_markdown

SAMPLES = [("alert_splunk.json", "malware"), ("alert_kuma.json", "bruteforce"), ("alert_phishing.json", "phishing")]


def load(samples, name):
    return parse_alert((samples / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name, category", SAMPLES)
@pytest.mark.parametrize("lang", ["ru", "en"])
def test_every_sample_gets_both_reasons(samples, name, category, lang):
    a = load(samples, name)
    reason = draft_reason(a, "TP", lang)
    escalation = draft_escalation(a, category, lang)
    assert a.name in reason and "True Positive" in reason
    assert a.hosts[0] in escalation and a.severity in escalation
    md = render_markdown(a, ReportInput("TP", reason, True, escalation, category, lang=lang))
    assert "не указано" not in md and "not specified" not in md


def test_bruteforce_counts_every_event(samples):
    reason = draft_reason(load(samples, "alert_kuma.json"), "TP")
    assert "8 неудачных входов (4625) и затем 1 успешный вход (4624)" in reason
    assert "45.155.205.233" in reason


def test_powershell_is_decoded(samples):
    reason = draft_reason(load(samples, "alert_splunk.json"), "TP")
    assert "IEX (New-Object Net.WebClient)" in reason
    assert "WINWORD.EXE" in reason and "закодированной командой" in reason


def test_phishing_signs(samples):
    reason = draft_reason(load(samples, "alert_phishing.json"), "TP")
    assert "spf/dmarc" in reason and "перешёл по ссылке" in reason
    assert "no-reply@" not in reason.split(".")[0]  # отправитель не считается затронутым пользователем


def test_reputation_used(samples):
    reason = draft_reason(load(samples, "alert_kuma.json"), "TP", reputation={"45.155.205.233": "malicious"})
    assert "Репутация подтверждает вредоносность: 45[.]155[.]205[.]233 (malicious)" in reason


def test_fp_draft(samples):
    a = load(samples, "alert_kuma.json")
    assert "False Positive" in draft_reason(a, "FP")
    clean = draft_reason(a, "FP", reputation={"45.155.205.233": "clean"})
    assert "чистую репутацию" in clean
