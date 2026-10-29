from __future__ import annotations

from datetime import date, timedelta

import pandas as pd
import streamlit as st

from soc_toolkit.reports import category_title, render_docx, render_html
from soc_toolkit.ui import state


def render() -> None:
    st.title("🗂️ Кейсы")
    store = state.case_store()
    stats = store.stats()
    m = st.columns(5)
    m[0].metric("Всего", stats["total"])
    m[1].metric("Открыто", stats["open"])
    m[2].metric("True Positive", stats["by_verdict"].get("TP", 0))
    m[3].metric("False Positive", stats["by_verdict"].get("FP", 0))
    m[4].metric("Эскалировано", stats["escalated"])

    c = st.columns([3, 1, 1, 2])
    text = c[0].text_input("Поиск по названию, заметкам, отчёту или IOC")
    verdict = c[1].selectbox("Вердикт", ["", "TP", "FP"], format_func=lambda v: v or "все")
    status = c[2].selectbox("Статус", ["", "open", "closed"], format_func=lambda v: v or "все")
    period = c[3].date_input("Период", (date.today() - timedelta(days=90), date.today()))
    d_from, d_to = (period[0].isoformat(), period[1].isoformat()) if len(period) == 2 else ("", "")
    cases = store.search(text, verdict, status, date_from=d_from, date_to=d_to)
    if not cases:
        st.info("Кейсов нет. Сохраните разбор на странице «Разбор алерта».")
        return
    df = pd.DataFrame([{"id": x.id, "дата": x.created.replace("T", " "), "алерт": x.title, "критичность": x.severity,
                        "вердикт": x.verdict, "категория": category_title(x.category), "эскалация": x.escalated,
                        "статус": x.status} for x in cases])
    st.dataframe(df, hide_index=True, width="stretch")

    case_id = st.selectbox("Открыть кейс", [x.id for x in cases],
                           format_func=lambda i: f"#{i} {next(x.title for x in cases if x.id == i)}")
    case = store.get(case_id)
    if not case:
        return
    a1, a2, a3, a4, a5 = st.columns(5)
    new_status = "closed" if case.status == "open" else "open"
    if a1.button("Закрыть" if case.status == "open" else "Переоткрыть", width="stretch"):
        store.set_status(case.id, new_status)  # type: ignore[arg-type]
        st.rerun()
    if a2.button("Открыть в разборе", width="stretch"):
        st.session_state["alert_raw"] = case.alert_json
        st.session_state["case_id"] = case.id
        st.switch_page(state.PAGES["alert"])
    if case.report_md:
        a3.download_button("⬇️ HTML", render_html(case.report_md), f"case_{case.id}.html", "text/html",
                           width="stretch")
        a4.download_button("⬇️ Word", render_docx(case.report_md), f"case_{case.id}.docx", width="stretch")
    if a5.button("🗑️ Удалить", width="stretch"):
        st.session_state["confirm_delete"] = case.id
    if st.session_state.get("confirm_delete") == case.id:
        st.error(f"Удалить кейс #{case.id} без возможности восстановления?")
        if st.button("Да, удалить"):
            store.delete(case.id)  # type: ignore[arg-type]
            st.session_state["confirm_delete"] = None
            st.rerun()

    t1, t2, t3 = st.tabs(["Отчёт", "Индикаторы", "Исходный алерт"])
    t1.markdown(case.report_md or "_Отчёт не сохранён._")
    iocs = store.iocs(case.id)  # type: ignore[arg-type]
    t2.dataframe(pd.DataFrame(iocs), hide_index=True, width="stretch")
    t3.code(case.alert_json, language="json")

    with st.expander("Статистика и экспорт"):
        if stats["top_iocs"]:
            st.markdown("**Индикаторы, встречавшиеся в нескольких кейсах**")
            st.dataframe(pd.DataFrame(stats["top_iocs"]), hide_index=True, width="stretch")
        if stats["by_category"]:
            st.bar_chart(pd.Series({category_title(k) or "—": v for k, v in stats["by_category"].items()}))
        st.download_button("⬇️ Все кейсы (JSON)", store.export_json(), "cases.json", "application/json")
