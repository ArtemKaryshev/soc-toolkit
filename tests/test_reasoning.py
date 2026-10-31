import pytest

from soc_toolkit.alerts import parse_alert
from soc_toolkit.reports import ReportInput, draft_escalation, draft_reason, render_markdown

SAMPLES = [("alert_splunk.json", "malware"), ("alert_kuma.json", "bruteforce"), ("alert_phishing.json", "phishing"),
           ("alert_defender_blocked.json", "malware"), ("alert_wazuh_fp.json", "generic")]


def load(samples, name):
    return parse_alert((samples / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name, category", SAMPLES)
@pytest.mark.parametrize("lang", ["ru", "en"])
def test_every_sample_gets_both_reasons(samples, name, category, lang):
    a = load(samples, name)
    reason = draft_reason(a, "TP", lang)
    escalation = draft_escalation(a, category, lang)
    assert a.name in reason and "True Positive" in reason
    assert escalation
    md = render_markdown(a, ReportInput("TP", reason, True, escalation, category, lang=lang))
    assert "не указано" not in md and "not specified" not in md


def test_bruteforce_counts_every_event(samples):
    reason = draft_reason(load(samples, "alert_kuma.json"), "TP")
    assert "8 неудачных входов (4625), затем 1 успешный (4624)" in reason
    assert "45.155.205.233" in reason


def test_powershell_is_decoded(samples):
    reason = draft_reason(load(samples, "alert_splunk.json"), "TP")
    assert "IEX (New-Object Net.WebClient)" in reason
    assert "WINWORD.EXE" in reason and "закодированной командой" in reason
    assert "- powershell.exe запущен из WINWORD.EXE" in reason   # признаки списком


def test_phishing_signs(samples):
    reason = draft_reason(load(samples, "alert_phishing.json"), "TP")
    assert "SPF/DMARC" in reason and "перешёл по ссылке" in reason
    assert "no-reply@" not in reason.split(".")[0]  # отправитель не считается затронутым пользователем


def test_reputation_used(samples):
    reason = draft_reason(load(samples, "alert_kuma.json"), "TP", reputation={"45.155.205.233": "malicious"})
    assert "считают вредоносными: 45[.]155[.]205[.]233 (malicious)" in reason


def test_fp_by_analyst_against_recommendation(samples):
    a = load(samples, "alert_kuma.json")
    text = draft_reason(a, "FP")
    assert "False Positive" in text and "[Укажите подтверждение" in text
    assert "Сработавшие признаки объясняются" in text


def test_fp_recommended_has_real_reasons(samples):
    text = draft_reason(load(samples, "alert_wazuh_fp.json"), "FP")
    assert "CcmExec.exe" in text and "Обращений к внешним адресам в алерте нет" in text
    assert "[Укажите" not in text


def test_escalation_follows_analyst_choice(samples):
    a = load(samples, "alert_defender_blocked.json")
    assert draft_escalation(a, "malware").startswith("Эскалация не требуется")
    forced = draft_escalation(a, "malware", escalate=True)
    assert "Требуется эскалация на L2" in forced


def test_no_escalation_shown_in_report(samples):
    a = load(samples, "alert_defender_blocked.json")
    why = draft_escalation(a, "malware")
    md = render_markdown(a, ReportInput("TP", "x", False, why, "malware"))
    assert why in md
