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
from soc_toolkit.triage import Assessment, assess, specific_remediation
from soc_toolkit.ui import state
from soc_toolkit.ui.state import VERDICT_STYLE
from soc_toolkit.ui.tabs.reputation import policy_gate, provider_picker, results_view, run_check

SAMPLES = [("Splunk: PowerShell", "alert_splunk.json"), ("KUMA: подбор пароля", "alert_kuma.json"),
           ("Фишинг", "alert_phishing.json"), ("Defender: заблокировано", "alert_defender_blocked.json"),
           ("Wazuh: SCCM (FP)", "alert_wazuh_fp.json")]
SEVERITY_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "informational": "🔵"}


def _load_sample(name: str) -> None:
    d = state.samples_dir()
    if d and (d / name).is_file():
        st.session_state["alert_raw"] = (d / name).read_text(encoding="utf-8")
        st.session_state["case_id"] = None


def _input_block() -> AlertSummary | None:
    uploaded = st.file_uploader("Загрузите алерт", type=["json", "txt", "log", "xml", "ndjson", "jsonl"],
                                label_visibility="collapsed")
    cols = st.columns(len(SAMPLES))
    for col, (label, name) in zip(cols, SAMPLES, strict=True):
        col.button(label, on_click=_load_sample, args=(name,), width="stretch")
    if uploaded is not None and st.session_state.get("_uploaded_name") != uploaded.name:
        st.session_state["alert_raw"] = uploaded.read().decode("utf-8", errors="replace")
        st.session_state["_uploaded_name"] = uploaded.name
        st.session_state["case_id"] = None
    raw = st.text_area("Алерт: JSON из Splunk, KUMA, Elastic, Wazuh, QRadar, Sentinel, Defender, CrowdStrike, а также "
                       "NDJSON, CEF, key=value или Windows XML", height=200, key="alert_raw")
    if not raw.strip():
        st.session_state["alert_summary"] = None
        return None
    try:
        summary = parse_alert(raw, allowlist=state.allowlist())
    except json.JSONDecodeError as e:
        st.error(f"Не удалось разобрать алерт: {e.msg}. Вставьте JSON, CEF, key=value или XML события.")
        return None
    st.session_state["alert_summary"] = summary
    return summary


def _overview(a: AlertSummary, x: Assessment) -> None:
    st.subheader(f"{SEVERITY_ICON.get(a.severity, '⚪')} {a.name or 'Алерт без названия'}")
    m = st.columns(4)
    m[0].metric("Критичность", a.severity or "—")
    m[1].metric("Формат", a.source_format)
    m[2].metric("Техник MITRE", len(a.mitre))
    m[3].metric("Индикаторов", len(a.iocs))
    _recommendation(x)
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


def _recommendation(x: Assessment) -> None:
    esc = "нужна" if x.escalate else "не нужна"
    text = f"**Рекомендация: {x.label()}** · уверенность {x.confidence}% · эскалация {esc} · категория " \
           f"«{category_title('fp' if x.verdict == 'FP' and x.certain else x.category)}»"
    if not x.certain:
        st.warning("🧭 " + text)
    elif x.verdict == "TP":
        st.error("🧭 " + text)
    else:
        st.success("🧭 " + text)
    with st.expander("Почему так: признаки и их вес"):
        rows = [{"вес": f"{f.weight:+d}" if f.weight else "0", "признак": f.ru} for f in x.factors + x.impact]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                     column_config={"признак": st.column_config.TextColumn(width="large")})
        st.caption(f"Сумма весов: {x.score}. True Positive от 3, False Positive при 0 и ниже, между ними нужна "
                   "ручная проверка.")
        st.markdown(f"**Эскалация.** {x.escalation_why['ru']}")
        st.caption("Это рекомендация по данным алерта, а не окончательное решение. Проверьте репутацию "
                   "индикаторов: её результат тоже учитывается. Признаки настраиваются в triage/signals.yaml.")


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


def _report(a: AlertSummary, x: Assessment) -> None:
    s = state.settings()
    alert_key = hash(st.session_state["alert_raw"])
    c1, c2, c3 = st.columns(3)
    verdict = c1.radio("Вердикт", ["TP", "FP"], horizontal=True, index=0 if x.verdict == "TP" else 1,
                       key=f"verdict_{alert_key}_{x.verdict}",
                       format_func=lambda v: "True Positive" if v == "TP" else "False Positive")
    lang = c2.radio("Язык отчёта", ["ru", "en"], horizontal=True,
                    index=0 if s.report.default_language == "ru" else 1,
                    format_func=lambda x: "Русский" if x == "ru" else "English")
    cats = categories()
    category = c3.selectbox("Категория", cats, index=cats.index(x.category) if x.category in cats else 0,
                            key=f"cat_{alert_key}_{x.category}", format_func=lambda c: category_title(c))
    if verdict != x.verdict:
        st.caption("⚠️ Вы выбрали вердикт, отличный от рекомендации. В обосновании отмечено место для "
                   "подтверждения, допишите его.")
    rep = st.session_state["reputation_results"]
    rep_verdicts = {k: v.verdict.value for k, v in rep.items()}
    # Тексты пересобираются при смене алерта, вердикта, категории, языка или результатов репутации;
    # правки аналитика сохраняются, пока эти входные данные не меняются.
    draft_key = f"{alert_key}_{verdict}_{category}_{lang}_{len(rep_verdicts)}"
    st.caption("Обоснование, эскалация и рекомендации составлены по уликам из алерта. "
               "Проверьте и допишите то, что выяснили сами.")
    reason = st.text_area("Обоснование вердикта", draft_reason(a, verdict, lang, rep_verdicts, x),
                          key=f"reason_{draft_key}", height=260)
    default_esc = x.escalate if verdict == x.verdict else verdict == "TP"
    escalate = st.toggle("Эскалировать на L2", value=default_esc, key=f"esc_toggle_{draft_key}")
    esc_reason = st.text_area("Причина эскалации" if escalate else "Почему эскалация не нужна",
                              draft_escalation(a, category, lang, escalate, rep_verdicts, x),
                              key=f"esc_{draft_key}_{escalate}", height=110)
    rem_default = list(dict.fromkeys(specific_remediation(a, x, lang, rep_verdicts) if verdict == x.verdict else []))
    rem_default += [r for r in default_remediation(category, verdict, lang) if r not in rem_default]
    remediation = st.text_area("Рекомендации (по одной в строке)", "\n".join(rem_default),
                               key=f"rem_{draft_key}", height=180)
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


def render() -> None:
    st.title("🚨 Разбор алерта")
    a = _input_block()
    if not a:
        st.info("Вставьте JSON алерта или загрузите пример. Приложение распознает сущности, индикаторы и техники "
                "MITRE, подскажет запросы для расследования и соберёт отчёт.")
        return
    rep = st.session_state["reputation_results"]
    x = assess(a, {k: v.verdict.value for k, v in rep.items()})
    _overview(a, x)
    st.divider()
    t_ioc, t_q, t_rep = st.tabs(["🔎 Индикаторы и репутация", "🧮 Запросы для расследования", "📝 Вердикт и отчёт"])
    with t_ioc:
        _iocs_and_reputation(a)
    with t_q:
        _queries(a)
    with t_rep:
        _report(a, x)
