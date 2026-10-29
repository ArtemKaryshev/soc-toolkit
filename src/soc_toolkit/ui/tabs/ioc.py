from __future__ import annotations

import pandas as pd
import streamlit as st

from soc_toolkit.ioc import IOCType, defang, extract, find_encoded, read_text, refang, to_csv, to_json, to_stix
from soc_toolkit.ui import state


def _load_sample() -> None:
    d = state.samples_dir()
    if d and (d / "phishing_email.txt").is_file():
        st.session_state["ioc_text"] = (d / "phishing_email.txt").read_text(encoding="utf-8")


def _email_panel(info) -> None:  # type: ignore[no-untyped-def]
    with st.expander("✉️ Разбор письма", expanded=True):
        c1, c2 = st.columns(2)
        c1.markdown(f"**Тема:** {info.subject}  \n**От:** `{info.sender}`  \n**Reply-To:** `{info.reply_to or '—'}`  \n"
                    f"**Return-Path:** `{info.return_path or '—'}`  \n**Кому:** {info.to}  \n**Дата:** {info.date}")
        auth = {"pass": "✅", "fail": "❌", "softfail": "⚠️", "none": "—", "": "—"}
        c2.markdown(f"**SPF:** {auth.get(info.spf, '⚠️')} {info.spf}  \n**DKIM:** {auth.get(info.dkim, '⚠️')} "
                    f"{info.dkim}  \n**DMARC:** {auth.get(info.dmarc, '⚠️')} {info.dmarc}  \n"
                    f"**Received-хопов:** {len(info.received)}")
        for w in info.warnings:
            st.warning(w)
        if info.attachments:
            st.dataframe(pd.DataFrame([{k: v for k, v in a.__dict__.items() if k != "strings"}
                                       for a in info.attachments]), hide_index=True, width="stretch")


def render() -> None:
    st.title("🔎 Индикаторы компрометации")
    tab_extract, tab_decode, tab_defang = st.tabs(["Извлечение", "Декодер", "Defang / Refang"])

    with tab_extract:
        left, right = st.columns([3, 1])
        with right:
            uploaded = st.file_uploader("Файл: txt, log, csv, json, html, eml",
                                        type=["txt", "log", "csv", "json", "html", "htm", "eml", "xml", "md"])
            st.button("Вставить пример", on_click=_load_sample)
            decode = st.toggle("Раскодировать base64 / PowerShell", value=True)
            only_external = st.toggle("Только внешние", value=False,
                                      help="Публичные IP, внешние домены, URL и хэши без allowlist")
            show_defanged = st.toggle("Показывать defanged", value=False)
            types = st.multiselect("Типы", [t.value for t in IOCType], placeholder="все")
        email_info = None
        with left:
            if uploaded is not None:
                try:
                    text, email_info = read_text(uploaded.name, uploaded.getvalue())
                except ValueError as e:
                    st.error(str(e))
                    text = ""
                st.caption(f"Файл: {uploaded.name}, {len(uploaded.getvalue()) / 1024:.1f} КБ")
            else:
                text = st.text_area("Текст: письмо, лог, тикет, отчёт TI", height=280, key="ioc_text")

        if email_info:
            _email_panel(email_info)
        if not text:
            return
        found = extract(text, decode=decode, allowlist=state.allowlist(), types=types or None)
        if only_external:
            found = [i for i in found if i.is_external]
        if not found:
            st.warning("Индикаторы не найдены.")
            return
        counts = pd.Series([i.type.value for i in found]).value_counts()
        st.markdown(" · ".join(f"**{t}** {n}" for t, n in counts.items()))
        st.dataframe(pd.DataFrame([i.as_row(show_defanged) for i in found]), hide_index=True, width="stretch",
                     column_config={"context": st.column_config.TextColumn("context", width="large")})
        c = st.columns(5)
        c[0].download_button("⬇️ CSV", to_csv(found, show_defanged), "iocs.csv", "text/csv", width="stretch")
        c[1].download_button("⬇️ JSON", to_json(found, show_defanged), "iocs.json", "application/json",
                             width="stretch")
        c[2].download_button("⬇️ STIX 2.1", to_stix(found), "iocs.stix.json", "application/json", width="stretch")
        c[3].download_button("⬇️ Список defanged", "\n".join(i.defanged for i in found), "iocs.txt",
                             width="stretch")
        external = [i for i in found if i.is_external]
        if c[4].button(f"→ В репутацию ({len(external)})", disabled=not external, width="stretch"):
            st.session_state["rep_input"] = "\n".join(i.value for i in external)
            st.switch_page(state.PAGES["reputation"])

    with tab_decode:
        blob = st.text_area("Командная строка, скрипт или base64", height=160, key="decode_input",
                            placeholder="powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj…")
        if blob:
            decoded = find_encoded(blob)
            if not decoded:
                st.info("Закодированных фрагментов не найдено.")
            for d in decoded:
                st.markdown(f"**{d.kind}** · `{d.source[:60]}…`")
                st.code(d.decoded, language="powershell", wrap_lines=True)
                inner = extract(d.decoded, decode=False)
                if inner:
                    st.caption("IOC внутри: " + ", ".join(f"{i.type.value}: {i.defanged}" for i in inner))

    with tab_defang:
        d1, d2 = st.columns(2)
        with d1:
            raw = st.text_area("Обычные → обезвредить", "http://evil.example.com/a.exe\n8.8.8.8\nuser@evil.com",
                               height=150)
            st.code("\n".join(defang(x.strip()) for x in raw.splitlines() if x.strip()) or " ")
        with d2:
            dfg = st.text_area("Обезвреженные → рабочий вид", "hxxps[://]evil[.]example[.]com/login\n1.2.3[.]4",
                               height=150)
            st.code(refang(dfg) or " ")

