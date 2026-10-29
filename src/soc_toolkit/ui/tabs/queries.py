from __future__ import annotations

import streamlit as st

from soc_toolkit.reference import technique_name
from soc_toolkit.ui import state


def render() -> None:
    st.title("🧮 Генератор запросов SPL / KUMA")
    engine = state.query_engine()
    alert = st.session_state.get("alert_summary")
    alert_params = alert.query_params() if alert else {}

    with st.expander("Окружение: индексы Splunk, период, лимит KUMA"):
        qs = engine.settings
        c = st.columns(4)
        env = {
            "win_index": c[0].text_input("Windows Event Log", qs.win_index),
            "sysmon_index": c[1].text_input("Sysmon", qs.sysmon_index),
            "proxy_index": c[2].text_input("Прокси", qs.proxy_index),
            "dns_index": c[3].text_input("DNS", qs.dns_index),
            "email_index": c[0].text_input("Почта", qs.email_index),
            "firewall_index": c[1].text_input("МСЭ", qs.firewall_index),
            "earliest": c[2].text_input("Период (earliest)", qs.earliest),
            "kuma_limit": c[3].number_input("LIMIT KUMA", 1, 100000, int(qs.kuma_limit)),
            "sysmon_sourcetype": st.text_input("sourcetype Sysmon", qs.sysmon_sourcetype),
        }
        st.caption("Постоянные значения задаются в config.toml, секция [queries]. Имена полей KUMA зависят от "
                   "нормализатора: если у вас иначе, поправьте шаблон или добавьте свой (custom_templates_dir).")

    c1, c2 = st.columns([1, 2])
    cats = engine.categories()
    category = c1.selectbox("Категория", cats)
    in_cat = [t for t in engine.templates if t.category == category]
    tid = c2.selectbox("Задача", [t.id for t in in_cat], format_func=lambda i: engine.by_id[i].title)
    t = engine.by_id[tid]
    st.caption(t.description)
    if t.mitre:
        st.caption("MITRE: " + ", ".join(f"[{m}](https://attack.mitre.org/techniques/{m.replace('.', '/')}/) "
                                         f"{technique_name(m)}" for m in t.mitre))

    params = {}
    if t.params:
        cols = st.columns(len(t.params))
        for col, p in zip(cols, t.params, strict=True):
            default = alert_params.get(p.name) or p.default
            params[p.name] = col.text_input(p.label, default, key=f"q_{tid}_{p.name}")
        if alert_params and any(alert_params.get(p.name) for p in t.params):
            st.caption("Часть параметров подставлена из текущего алерта.")
    r = engine.render(tid, params, env)
    q1, q2 = st.columns(2)
    q1.markdown("**Splunk SPL**")
    q1.code(r.spl, language="sql", wrap_lines=True)
    q2.markdown("**KUMA SQL** <small>(период задаётся в интерфейсе поиска KUMA)</small>", unsafe_allow_html=True)
    q2.code(r.kuma, language="sql", wrap_lines=True)

    with st.expander(f"Все шаблоны ({len(engine.templates)})"):
        st.dataframe([{"id": x.id, "категория": x.category, "задача": x.title, "MITRE": ", ".join(x.mitre),
                       "источник": x.source} for x in engine.templates], hide_index=True, width="stretch")
