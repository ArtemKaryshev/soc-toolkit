"""Общие объекты и состояние сессии интерфейса."""

from __future__ import annotations

from typing import Any

import streamlit as st

from soc_toolkit.cases import CaseStore
from soc_toolkit.config import ENV_KEYS, PACKAGE_DIR, ConfigError, Settings, load_settings, setup_logging
from soc_toolkit.ioc import Allowlist
from soc_toolkit.queries import QueryEngine
from soc_toolkit.reputation import ReputationService

# Страницы навигации по url_path: заполняется в app.py, нужно для st.switch_page
PAGES: dict[str, Any] = {}

DEFAULTS: dict[str, Any] = {
    "alert_raw": "",
    "alert_summary": None,
    "case_id": None,
    "reputation_results": {},   # значение IOC -> AggregatedResult
    "policy_ack": None,
    "ioc_text": "",
    "rep_input": "",
}


def init() -> None:
    for k, v in DEFAULTS.items():
        st.session_state.setdefault(k, v)
    try:
        s = settings()
    except ConfigError as e:
        st.error(str(e).replace("\n", "  \n"))
        st.stop()
    if st.session_state["policy_ack"] is None:
        st.session_state["policy_ack"] = s.reputation.policy_acknowledged


@st.cache_resource
def settings() -> Settings:
    s = load_settings()
    s.api_keys.update(secret_keys())
    setup_logging(s)
    return s


def secret_keys() -> dict[str, str]:
    """Ключи из секретов Streamlit (Streamlit Community Cloud: Settings → Secrets).

    Принимаются оба вида: VT_API_KEY = "..." в корне или секция [api_keys] как в config.toml.
    Секреты важнее config.toml, но переменные окружения уже учтены в load_settings.
    """
    try:
        secrets: Any = dict(st.secrets)
    except Exception:  # файла секретов нет: обычный локальный запуск
        return {}
    section = secrets.get("api_keys") or {}
    out = {}
    for name, env in ENV_KEYS.items():
        value = secrets.get(env) or section.get(name)
        if value:
            out[name] = str(value).strip()
    return out


@st.cache_resource
def allowlist() -> Allowlist:
    s = settings()
    from pathlib import Path

    paths = [PACKAGE_DIR / "ioc" / "allowlist.yaml"] if s.ioc.use_builtin_allowlist else []
    if s.ioc.allowlist_file:
        paths.append(Path(s.ioc.allowlist_file).expanduser())
    return Allowlist.load(paths)


@st.cache_resource
def reputation_service() -> ReputationService:
    return ReputationService(settings())


@st.cache_resource
def query_engine() -> QueryEngine:
    return QueryEngine(settings().queries)


@st.cache_resource
def case_store() -> CaseStore:
    return CaseStore(settings().cases_path)


def samples_dir() -> Any:
    from pathlib import Path

    for p in (Path.cwd() / "samples", PACKAGE_DIR.parents[1] / "samples"):
        if p.is_dir():
            return p
    return None


VERDICT_STYLE = {"malicious": "🔴 malicious", "suspicious": "🟠 suspicious", "clean": "🟢 clean",
                 "unknown": "⚪ unknown", "error": "⚠️ error", "skipped": "⏭️ skipped"}
