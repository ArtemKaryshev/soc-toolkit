"""Веб-интерфейс SOC Toolkit (Streamlit). Запуск: soc-toolkit ui  или  streamlit run src/soc_toolkit/ui/app.py"""

from __future__ import annotations

import sys
from pathlib import Path

# Запуск без установки пакета: добавляем src в путь
_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import streamlit as st  # noqa: E402

from soc_toolkit import __version__  # noqa: E402
from soc_toolkit.ui import state  # noqa: E402
from soc_toolkit.ui.tabs import alert, cases, ioc, queries, reference, reputation, settings  # noqa: E402

st.set_page_config(page_title="SOC Toolkit", page_icon="🛡️", layout="wide")
state.init()

pages = [
    st.Page(alert.render, title="Разбор алерта", icon="🚨", url_path="alert", default=True),
    st.Page(ioc.render, title="IOC", icon="🔎", url_path="ioc"),
    st.Page(reputation.render, title="Репутация", icon="🌐", url_path="reputation"),
    st.Page(queries.render, title="Запросы SPL / KUMA", icon="🧮", url_path="queries"),
    st.Page(reference.render, title="Справочник", icon="📚", url_path="reference"),
    st.Page(cases.render, title="Кейсы", icon="🗂️", url_path="cases"),
    st.Page(settings.render, title="Настройки", icon="⚙️", url_path="settings"),
]
state.PAGES.update({p.url_path: p for p in pages})

with st.sidebar:
    st.markdown(f"### 🛡️ SOC Toolkit\n<small>v{__version__} · работает локально</small>", unsafe_allow_html=True)
    current = st.session_state.get("alert_summary")
    if current:
        st.info(f"Текущий алерт:\n\n**{current.name or 'без названия'}**")

st.navigation(pages, position="sidebar").run()
