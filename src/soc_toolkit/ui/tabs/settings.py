from __future__ import annotations

import pandas as pd
import streamlit as st

from soc_toolkit import __version__
from soc_toolkit.config import PACKAGE_DIR, app_home
from soc_toolkit.reference import lolbas, mitre, store
from soc_toolkit.ui import state


def render() -> None:
    st.title("⚙️ Настройки")
    s = state.settings()
    st.markdown(f"""
| | |
|---|---|
| Версия | {__version__} |
| Файл конфигурации | `{s.source or "не найден, используются значения по умолчанию"}` |
| Домашняя папка | `{s.home}` |
| База кейсов | `{s.cases_path}` |
| Кеш репутации | `{s.cache_path}` |
| Журнал работы | `{s.log_path}` |
""")
    if not s.source:
        st.info("Чтобы задать ключи API и параметры, выполните `soc-toolkit init` или скопируйте "
                f"`config.example.toml` в `{app_home() / 'config.toml'}`, затем перезапустите приложение.")
        st.download_button("⬇️ config.example.toml", (PACKAGE_DIR / "config.example.toml").read_text(encoding="utf-8"),
                           "config.toml")

    st.subheader("Сервисы репутации")
    svc = state.reputation_service()
    st.dataframe(pd.DataFrame(svc.status()), hide_index=True, width="stretch",
                 column_config={"signup": st.column_config.LinkColumn("получить ключ")})
    st.caption(f"Политика подтверждена: {'да' if s.reputation.policy_acknowledged else 'нет'} · "
               f"внутренние индикаторы: {'отправляются' if s.reputation.allow_internal else 'не отправляются'} · "
               f"TTL кеша: {s.reputation.cache_ttl_hours} ч · прокси: {s.reputation.proxy or 'нет'}")

    st.subheader("Справочники")
    st.write(f"MITRE ATT&CK от {mitre()['version']}: {len(mitre()['techniques'])} техник, "
             f"{len(mitre()['groups'])} групп. LOLBAS: {len(lolbas())} записей.")
    if st.button("Обновить MITRE ATT&CK и LOLBAS из интернета"):
        from soc_toolkit.reference.updater import update

        with st.spinner("Скачиваю…"):
            try:
                result = update(app_home() / "data", proxy=s.reputation.proxy)
            except Exception as e:
                st.error(f"Не удалось обновить: {e}")
            else:
                store.mitre.cache_clear()
                store.lolbas.cache_clear()
                store._technique_index.cache_clear()
                st.success(f"Готово: {result}")

    st.subheader("Сброс")
    if st.button("Перечитать config.toml"):
        st.cache_resource.clear()
        st.session_state["policy_ack"] = None
        st.rerun()
