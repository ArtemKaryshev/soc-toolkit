from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from soc_toolkit.alerts import AlertSummary, parse_alert
from soc_toolkit.cases import Case
from soc_toolkit.reference import technique
from soc_toolkit.reports import (
    ReportInput,
    categories,
    category_title,
    default_remediation,
    draft_escalation,
    draft_reason,
    render_docx,
    render_html,
    render_markdown,
)
from soc_toolkit.ui import state
from soc_toolkit.ui.state import VERDICT_STYLE
from soc_toolkit.ui.tabs.reputation import policy_gate, provider_picker, results_view, run_check

SEVERITY_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "informational": "🔵"}


def _load_sample(name: str) -> None:
    d = state.samples_dir()
    if d and (d / name).is_file():
        st.session_state["alert_raw"] = (d / name).read_text(encoding="utf-8")
        st.session_state["case_id"] = None


def _input_block() -> AlertSummary | None:
    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    uploaded = c1.file_uploader("Загрузите JSON алерта", type=["json"], label_visibility="collapsed")
    c2.button("Пример: Splunk", on_click=_load_sample, args=("alert_splunk.json",), width="stretch")
    c3.button("Пример: KUMA", on_click=_load_sample, args=("alert_kuma.json",), width="stretch")
    c4.button("Пример: фишинг", on_click=_load_sample, args=("alert_phishing.json",), width="stretch")
    if uploaded is not None and st.session_state.get("_uploaded_name") != uploaded.name:
        st.session_state["alert_raw"] = uploaded.read().decode("utf-8", errors="replace")
        st.session_state["_uploaded_name"] = uploaded.name
        st.session_state["case_id"] = None
    raw = st.text_area("JSON алерта (Splunk, KUMA, Elastic, Defender или любой JSON)", height=200, key="alert_raw")
    if not raw.strip():
        st.session_state["alert_summary"] = None
        return None
    try:
        summary = parse_alert(raw, allowlist=state.allowlist())
    except json.JSONDecodeError as e:
        st.error(f"Некорректный JSON: {e}")
        return None
    st.session_state["alert_summary"] = summary
    return summary


def _overview(a: AlertSummary) -> None:
    st.subheader(f"{SEVERITY_ICON.get(a.severity, '⚪')} {a.name or 'Алерт без названия'}")
    m = st.columns(4)
    m[0].metric("Критичность", a.severity or "—")
    m[1].metric("Формат", a.source_format)
    m[2].metric("Техник MITRE", len(a.mitre))
    m[3].metric("Индикаторов", len(a.iocs))
    if a.times:
        span = a.first_seen if a.first_seen == a.last_seen else f"{a.first_seen} → {a.last_seen}"
        st.caption(f"🕒 Время активности: {span}")
    if a.description:
        st.caption(a.description)

    left, right = st.columns(2)
    with left:
        st.markdown("**Затронутые объекты**")
        rows = []
        for label, values in (("Хосты", a.hosts), ("Пользователи", a.users), ("IP-источники", a.src_ips),
                              ("IP-назначения", a.dest_ips), ("Процессы", a.processes),
                              ("Родители", a.parent_processes), ("Файлы", a.files), ("Хэши", a.hashes),
                              ("URL", a.urls), ("Домены", a.domains), ("EventID", a.event_ids)):
            rows.extend({"тип": label, "значение": v} for v in values)
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        else:
            st.caption("Поля не распознаны. Дополните сопоставление в alerts/field_map.yaml.")
        for c in a.commands:
            st.code(c, language="powershell", wrap_lines=True)
    with right:
        st.markdown("**MITRE ATT&CK**")
        if a.mitre:
            mrows = []
            for h in a.mitre:
                t = technique(h.technique)
                mrows.append({"ID": h.technique, "Техника": t["full_name"] if t else "",
                              "Тактики": ", ".join(t["tactics"]) if t else "",
                              "Основание": h.reason, "url": t["url"] if t else ""})
            st.dataframe(pd.DataFrame(mrows), hide_index=True, width="stretch",
                         column_config={"url": st.column_config.LinkColumn("url", display_text="открыть")})
        else:
            st.caption("Техники не определены.")
        if a.timeline:
            st.markdown("**Хронология**")
            st.dataframe(pd.DataFrame([{"время": e.time, "событие": e.summary} for e in a.timeline]),
                         hide_index=True, width="stretch")

    # Встречались ли индикаторы в прошлых разборах
    external = [i for i in a.iocs if i.is_external]
    seen = state.case_store().sightings([i.value for i in external], exclude_case=st.session_state["case_id"])
    if seen:
        st.warning("🔁 Индикаторы уже встречались в прошлых кейсах: " +
                   "; ".join(f"`{v}` → " + ", ".join(f"#{c}" for c in ids) for v, ids in seen.items()))


def _iocs_and_reputation(a: AlertSummary) -> None:
    rep = st.session_state["reputation_results"]
    rows = [{**i.as_row(), "репутация": VERDICT_STYLE.get(rep[i.value].verdict.value, "") if i.value in rep else ""}
            for i in a.iocs]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                 column_config={"context": st.column_config.TextColumn("context", width="large")})
    external = [i for i in a.iocs if i.is_external]
    if not external:
        st.caption("Внешних индикаторов для проверки нет.")
        return
    with st.expander(f"Проверить репутацию внешних индикаторов ({len(external)})"):
        if policy_gate("alert_ack"):
            providers = provider_picker("alert_providers")
            if st.button("Проверить", type="primary", disabled=not providers, key="alert_rep_go"):
                st.session_state["alert_rep_last"] = run_check(external, providers)
            results_view(st.session_state.get("alert_rep_last", []), "alert_rep")


def _queries(a: AlertSummary) -> None:
    engine = state.query_engine()
    params = a.query_params()
    suggested = engine.suggest(params)
    if not suggested:
        st.caption("Для этого алерта не нашлось подходящих шаблонов. Откройте страницу «Запросы».")
        return
    tid = st.selectbox("Запрос для расследования", suggested, format_func=lambda i: engine.by_id[i].title)
    r = engine.render(tid, params)
    st.caption("Параметры взяты из алерта: " + ", ".join(f"{k}={v}" for k, v in r.params.items()))
    c1, c2 = st.columns(2)
    c1.markdown("**Splunk SPL**")
    c1.code(r.spl, language="sql", wrap_lines=True)
    c2.markdown("**KUMA SQL**")
    c2.code(r.kuma, language="sql", wrap_lines=True)


def _report(a: AlertSummary) -> None:
    s = state.settings()
    c1, c2, c3 = st.columns(3)
    verdict = c1.radio("Вердикт", ["TP", "FP"], horizontal=True,
                       format_func=lambda v: "True Positive" if v == "TP" else "False Positive")
    lang = c2.radio("Язык отчёта", ["ru", "en"], horizontal=True,
                    index=0 if s.report.default_language == "ru" else 1,
                    format_func=lambda x: "Русский" if x == "ru" else "English")
    cats = categories()
    guess = _guess_category(a)
    category = c3.selectbox("Категория", cats, index=cats.index(guess), format_func=lambda c: category_title(c))
    rep = st.session_state["reputation_results"]
    rep_verdicts = {k: v.verdict.value for k, v in rep.items()}
    # Черновики пересобираются при смене алерта, вердикта, категории, языка или результатов репутации;
    # правки аналитика сохраняются, пока эти входные данные не меняются.
    draft_key = f"{hash(st.session_state['alert_raw'])}_{verdict}_{category}_{lang}_{len(rep_verdicts)}"
    st.caption("Обоснование и причина эскалации заполнены черновиком по уликам из алерта. "
               "Проверьте и допишите то, что выяснили сами.")
    reason = st.text_area("Обоснование вердикта", draft_reason(a, verdict, lang, rep_verdicts),
                          key=f"reason_{draft_key}", height=170)
    escalate = st.toggle("Эскалировать на L2", value=verdict == "TP")
    esc_reason = st.text_area("Причина эскалации", draft_escalation(a, category, lang) if escalate else "",
                              disabled=not escalate, key=f"esc_{draft_key}_{escalate}", height=100)
    remediation = st.text_area("Рекомендации (по одной в строке)",
                               "\n".join(default_remediation(category, verdict, lang)),
                               key=f"rem_{category}_{verdict}_{lang}", height=150)
    notes = st.text_area("Заметки аналитика (необязательно)", key="rep_notes")

    inp = ReportInput(
        verdict=verdict, reason=reason, escalate=escalate, escalation_reason=esc_reason, category=category,
        remediation=[r.strip() for r in remediation.splitlines() if r.strip()], notes=notes, lang=lang,
        analyst=s.report.analyst_name, case_id=st.session_state["case_id"], defang=s.report.defang_indicators,
        reputation=rep_verdicts,
    )
    md = render_markdown(a, inp, s.report.custom_templates_dir)

    b = st.columns(5)
    if b[0].button("💾 Сохранить кейс", type="primary", width="stretch"):
        store = state.case_store()
        case = Case(id=st.session_state["case_id"], title=a.name or "Без названия", severity=a.severity,
                    verdict=verdict, category=category, escalated=escalate, analyst=inp.analyst,
                    source_format=a.source_format, first_seen=a.first_seen,
                    alert_json=st.session_state["alert_raw"], notes=notes)
        case_id = store.save(case, a.iocs, inp.reputation)
        inp.case_id = case_id
        md = render_markdown(a, inp, s.report.custom_templates_dir)
        case.report_md = md
        store.save(case)
        st.session_state["case_id"] = case_id
        st.toast(f"Кейс #{case_id} сохранён")
    b[1].download_button("⬇️ Markdown", md, f"alert_report_{lang}.md", "text/markdown", width="stretch")
    b[2].download_button("⬇️ HTML", render_html(md, lang), f"alert_report_{lang}.html", "text/html", width="stretch")
    b[3].download_button("⬇️ Word", render_docx(md), f"alert_report_{lang}.docx",
                         "application/vnd.openxmlformats-officedocument.wordprocessingml.document", width="stretch")
    if st.session_state["case_id"]:
        b[4].caption(f"Кейс #{st.session_state['case_id']}")

    t1, t2 = st.tabs(["Предпросмотр", "Текст для копирования"])
    t1.markdown(md)
    t2.code(md, language="markdown", wrap_lines=True)


def _guess_category(a: AlertSummary) -> str:
    ids = {h.technique.split(".")[0] for h in a.mitre}
    if ids & {"T1486", "T1490"}:
        return "ransomware"
    if ids & {"T1003", "T1558"}:
        return "credential_access"
    if ids & {"T1110"}:
        return "bruteforce"
    if ids & {"T1566"}:
        return "phishing"
    if ids & {"T1021", "T1570"}:
        return "lateral"
    if ids & {"T1041", "T1567"}:
        return "exfiltration"
    if ids & {"T1059", "T1204", "T1105", "T1218"}:
        return "malware"
    return "generic"


def render() -> None:
    st.title("🚨 Разбор алерта")
    a = _input_block()
    if not a:
        st.info("Вставьте JSON алерта или загрузите пример. Приложение распознает сущности, индикаторы и техники "
                "MITRE, подскажет запросы для расследования и соберёт отчёт.")
        return
    _overview(a)
    st.divider()
    t_ioc, t_q, t_rep = st.tabs(["🔎 Индикаторы и репутация", "🧮 Запросы для расследования", "📝 Вердикт и отчёт"])
    with t_ioc:
        _iocs_and_reputation(a)
    with t_q:
        _queries(a)
    with t_rep:
        _report(a)
