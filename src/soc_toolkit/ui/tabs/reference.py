from __future__ import annotations

import pandas as pd
import streamlit as st

from soc_toolkit import reference as ref
from soc_toolkit.reference import store


def _events() -> None:
    c1, c2 = st.columns([3, 1])
    q = c1.text_input("Номер события или слово (4625, kerberos, lsass, rdp)", key="ev_q")
    logs = sorted({str(e["log"]) for e in store.eventids()["events"]})
    log = c2.selectbox("Журнал", ["все", *logs])
    rows = ref.search_events(q, "" if log == "все" else log)
    st.caption(f"Найдено: {len(rows)}")
    df = pd.DataFrame(rows)
    if not df.empty:
        df["mitre"] = df.get("mitre").apply(lambda v: ", ".join(v) if isinstance(v, list) else "")
        st.dataframe(df[["id", "log", "title", "fields", "tips", "mitre"]], hide_index=True, width="stretch",
                     column_config={"tips": st.column_config.TextColumn("на что смотреть", width="large"),
                                    "fields": st.column_config.TextColumn("ключевые поля", width="medium")})
    with st.expander("Таблицы: типы входа, коды NTSTATUS, ошибки Kerberos, шифрование билетов"):
        data = store.eventids()
        t1, t2, t3, t4 = st.tabs(["Logon Type", "NTSTATUS", "Kerberos", "Ticket encryption"])
        t1.dataframe(data["logon_types"], hide_index=True, width="stretch")
        t2.dataframe(data["ntstatus"], hide_index=True, width="stretch")
        t3.dataframe(data["kerberos_errors"], hide_index=True, width="stretch")
        t4.dataframe(data["ticket_encryption"], hide_index=True, width="stretch")


def _mitre() -> None:
    m = ref.mitre()
    c1, c2, c3 = st.columns([3, 2, 1])
    q = c1.text_input("ID или ключевые слова (T1059, lsass, phishing)", key="mitre_q")
    tactics = {t["shortname"]: t["name"] for t in m["tactics"]}
    tactic = c2.selectbox("Тактика", ["", *tactics], format_func=lambda x: tactics.get(x, "все тактики"))
    subs = c3.toggle("Подтехники", value=True)
    rows = ref.search_techniques(q, tactic, subs)
    st.caption(f"ATT&CK Enterprise от {m['version']} · найдено техник: {len(rows)}")
    df = pd.DataFrame([{"id": t["id"], "техника": t["full_name"], "тактики": ", ".join(t["tactics"]),
                        "платформы": ", ".join(t["platforms"]), "url": t["url"]} for t in rows])
    if df.empty:
        return
    st.dataframe(df, hide_index=True, width="stretch",
                 column_config={"url": st.column_config.LinkColumn("url", display_text="attack.mitre.org")})
    pick = st.selectbox("Подробнее", [t["id"] for t in rows[:300]],
                        format_func=lambda i: f"{i} {ref.technique_name(i)}")
    t = ref.technique(pick)
    if t:
        st.markdown(f"#### {t['id']} {t['full_name']}")
        st.markdown(t["description"])
        if t["detection"]:
            st.markdown(f"**Обнаружение:** {t['detection']}")
        if t["data_sources"]:
            st.caption("Источники данных: " + "; ".join(t["data_sources"]))
        st.markdown(f"[Открыть на attack.mitre.org]({t['url']})")


def _lolbas() -> None:
    c1, c2 = st.columns([3, 1])
    q = c1.text_input("Бинарник или действие (certutil, download, uac bypass)", key="lol_q")
    cat = c2.selectbox("Категория", ["", *store.lolbas_categories()], format_func=lambda x: x or "все")
    rows = ref.search_lolbas(q, cat)
    st.caption(f"Найдено: {len(rows)} из {len(ref.lolbas())}")
    st.dataframe(pd.DataFrame([{"бинарник": r["name"], "описание": r["description"],
                                "категории": ", ".join(r["categories"]), "MITRE": ", ".join(r["mitre"]),
                                "url": r["url"]} for r in rows]), hide_index=True, width="stretch",
                 column_config={"url": st.column_config.LinkColumn("url", display_text="lolbas")})
    if rows:
        pick = st.selectbox("Команды и детект", [r["name"] for r in rows[:300]])
        e = next(r for r in rows if r["name"] == pick)
        for c in e["commands"]:
            st.markdown(f"**{c['category']}** · {c['description']} · `{c['mitre']}` · права: {c['privileges']}")
            st.code(c["command"], language="powershell", wrap_lines=True)
        if e["paths"]:
            st.caption("Пути: " + "; ".join(e["paths"]))
        if e["detection"]:
            with st.expander("Детект (Sigma, Elastic, IOC)"):
                for d in e["detection"]:
                    st.markdown(f"- {d}")


def _groups() -> None:
    q = st.text_input("Группировка или алиас (APT29, Lazarus, FIN7)", key="grp_q")
    rows = ref.search_groups(q)
    st.dataframe(pd.DataFrame([{"id": g["id"], "название": g["name"], "алиасы": ", ".join(g["aliases"]),
                                "описание": g["description"], "url": g["url"]} for g in rows]),
                 hide_index=True, width="stretch",
                 column_config={"url": st.column_config.LinkColumn("url", display_text="mitre"),
                                "описание": st.column_config.TextColumn("описание", width="large")})


def render() -> None:
    st.title("📚 Справочник")
    st.caption("Работает офлайн. Обновить MITRE и LOLBAS можно на странице «Настройки».")
    t1, t2, t3, t4 = st.tabs(["Windows EventID", "MITRE ATT&CK", "LOLBAS", "APT-группировки"])
    with t1:
        _events()
    with t2:
        _mitre()
    with t3:
        _lolbas()
    with t4:
        _groups()
