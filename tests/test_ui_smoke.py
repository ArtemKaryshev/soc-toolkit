"""Дымовой тест интерфейса: каждая страница отрисовывается без исключений."""

import pytest
from streamlit.testing.v1 import AppTest

from soc_toolkit.config import PACKAGE_DIR

APP = str(PACKAGE_DIR / "ui" / "app.py")
PAGES = ["alert", "ioc", "reputation", "queries", "reference", "cases", "settings"]


@pytest.fixture(autouse=True)
def fresh_resources():
    # кешированные ресурсы (настройки, база кейсов) не должны переходить между тестами
    import streamlit as st

    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def _page(name: str) -> None:
    import importlib

    from soc_toolkit.ui import state

    state.init()
    importlib.import_module(f"soc_toolkit.ui.tabs.{name}").render()


def test_app_entrypoint():
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception, at.exception


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(page):
    at = AppTest.from_function(_page, args=(page,), default_timeout=60).run()
    assert not at.exception, at.exception


def test_alert_workflow(samples):
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    at.text_area(key="alert_raw").set_value((samples / "alert_splunk.json").read_text(encoding="utf-8")).run()
    assert not at.exception
    assert any("Suspicious Encoded PowerShell" in h.value for h in at.subheader)
    save = next(b for b in at.button if "Сохранить кейс" in b.label)
    save.click().run()
    assert not at.exception
    assert at.session_state["case_id"] == 1


@pytest.mark.parametrize("sample, verdict, escalate", [
    ("alert_splunk.json", "True Positive", True), ("alert_kuma.json", "True Positive", True),
    ("alert_phishing.json", "True Positive", True), ("alert_defender_blocked.json", "True Positive", False),
    ("alert_wazuh_fp.json", "False Positive", False),
])
def test_report_prefilled_for_samples(samples, sample, verdict, escalate):
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.text_area(key="alert_raw").set_value((samples / sample).read_text(encoding="utf-8")).run()
    assert not at.exception
    banner = [m.value for m in list(at.error) + list(at.success) + list(at.warning) if "Рекомендация" in m.value]
    assert banner and verdict in banner[0]
    reason = next(t for t in at.text_area if t.label == "Обоснование вердикта")
    esc_label = "Причина эскалации" if escalate else "Почему эскалация не нужна"
    escalation = next(t for t in at.text_area if t.label == esc_label)
    assert verdict in reason.value and escalation.value
    assert ("эскалация на L2" in escalation.value) == escalate
    preview = "\n".join(m.value for m in at.markdown)
    assert "не указано" not in preview


def test_unparseable_alert_shows_error():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.text_area(key="alert_raw").set_value("просто текст").run()
    assert not at.exception
    assert any("Не удалось разобрать алерт" in e.value for e in at.error)


def test_broken_config_shows_error(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[api_keys]\nabuseipdb = "abc\n', encoding="utf-8")
    monkeypatch.setenv("SOC_TOOLKIT_CONFIG", str(cfg))
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    assert any("закрывающей кавычки" in e.value for e in at.error)


def test_keys_from_streamlit_secrets(monkeypatch):
    import streamlit as st

    from soc_toolkit.ui import state

    fake = {"VT_API_KEY": " vt-key ", "api_keys": {"abuseipdb": "abuse-key"}}
    monkeypatch.setattr(st, "secrets", fake)
    assert state.secret_keys() == {"virustotal": "vt-key", "abuseipdb": "abuse-key"}
    assert state.settings().api_keys["virustotal"] == "vt-key"
