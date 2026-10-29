import io
import zipfile

import pytest

from soc_toolkit.alerts import parse_alert
from soc_toolkit.reports import (
    ReportInput,
    categories,
    default_remediation,
    render_docx,
    render_html,
    render_markdown,
)

SECTIONS = ["Time of activity", "List of Affected Entities", "Reason for Classifying as", "Reason for Escalating",
            "Recommended Remediation Actions", "List of Attack Indicators"]


@pytest.fixture
def splunk(samples):
    return parse_alert((samples / "alert_splunk.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("lang", ["ru", "en"])
def test_sections_present(splunk, lang):
    md = render_markdown(splunk, ReportInput("TP", "Подтверждено", True, "Нужен анализ", "malware", lang=lang))
    for s in SECTIONS:
        assert s in md
    assert "True Positive" in md


def test_indicators_defanged_and_filtered(splunk):
    md = render_markdown(splunk, ReportInput("TP"))
    indicators = md.split("List of Attack Indicators")[1].split("##")[0]
    assert "185[.]220[.]101[.]45" in indicators
    assert "10[.]10[.]20[.]17" not in indicators          # внутренний адрес не индикатор атаки
    assert "powershell.exe" not in indicators              # системный бинарник не индикатор
    assert "invoice_2026.docm" in indicators


def test_fp_no_escalation_and_fp_remediation(splunk):
    md = render_markdown(splunk, ReportInput("FP", "Тестовый запуск администратора", lang="ru"))
    assert "False Positive" in md and "Эскалация не требуется." in md
    assert default_remediation("malware", "FP")[0] in md


def test_mitre_table_and_reputation(splunk):
    md = render_markdown(splunk, ReportInput("TP", reputation={"185.220.101.45": "malicious"}))
    assert "Command and Scripting Interpreter: PowerShell" in md
    assert "185[.]220[.]101[.]45` — malicious" in md


def test_timeline_and_case_id(samples):
    a = parse_alert((samples / "alert_kuma.json").read_text(encoding="utf-8"))
    md = render_markdown(a, ReportInput("TP", case_id=42, analyst="Artem"))
    assert "№42" in md and "Artem" in md and "Хронология событий" in md


def test_custom_template_dir(splunk, tmp_path):
    (tmp_path / "report_ru.md.j2").write_text("CUSTOM {{ a.name }}", encoding="utf-8")
    assert render_markdown(splunk, ReportInput("TP"), str(tmp_path)).startswith("CUSTOM Suspicious")


def test_html_and_docx(splunk):
    md = render_markdown(splunk, ReportInput("TP", "ok"))
    html = render_html(md)
    assert html.startswith("<!doctype html>") and "<table>" in html and "<h2>" in html
    data = render_docx(md)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        xml = z.read("word/document.xml").decode()
    assert "Suspicious Encoded PowerShell Execution" in xml and "Recommended Remediation Actions" in xml


def test_categories_have_both_languages():
    for c in [*categories(), "fp"]:
        assert default_remediation(c, "TP" if c != "fp" else "FP", "ru")
        assert default_remediation(c, "TP" if c != "fp" else "FP", "en")
