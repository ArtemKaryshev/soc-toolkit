from __future__ import annotations

import pandas as pd
import streamlit as st

from soc_toolkit.ioc import IOC, extract
from soc_toolkit.reputation import POLICY_WARNING, AggregatedResult
from soc_toolkit.ui import state
from soc_toolkit.ui.state import VERDICT_STYLE


def policy_gate(key: str) -> bool:
    """Предупреждение о политике и подтверждение. Возвращает True, если можно отправлять."""
    if st.session_state["policy_ack"]:
        return True
    st.warning("⚠️ " + POLICY_WARNING)
    if st.checkbox("Я понимаю риски и имею право отправлять эти индикаторы во внешние сервисы", key=key):
        st.session_state["policy_ack"] = True
        st.rerun()
    return False


def run_check(iocs: list[IOC], providers: list[str]) -> list[AggregatedResult]:
    svc = state.reputation_service()
    svc.settings.reputation.policy_acknowledged = bool(st.session_state["policy_ack"])
    bar = st.progress(0.0, text="Проверяю…")
    results = svc.check(iocs, providers, progress=lambda d, t: bar.progress(d / max(t, 1), text=f"Запросов: {d}/{t}"))
    bar.empty()
    for r in results:
        st.session_state["reputation_results"][r.indicator] = r
    return results


def results_view(results: list[AggregatedResult], key: str) -> None:
    if not results:
        return
    summary = pd.DataFrame([{
        "индикатор": a.indicator, "тип": a.ioc_type, "итог": VERDICT_STYLE.get(a.verdict.value, a.verdict.value),
        "по сервисам": a.summary,
    } for a in results])
    st.dataframe(summary, hide_index=True, width="stretch")
    rows = []
    for a in results:
        for r in a.results:
            rows.append({"индикатор": a.indicator, "сервис": r.provider,
                         "вердикт": VERDICT_STYLE.get(r.verdict.value, r.verdict.value), "оценка": r.score,
                         "детали": r.summary or r.error, "кеш": "✓" if r.cached else "", "ссылка": r.link})
    with st.expander("Подробно по каждому сервису", expanded=False):
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                     column_config={"ссылка": st.column_config.LinkColumn("ссылка", display_text="открыть")})
    st.download_button("⬇️ CSV", pd.DataFrame(rows).to_csv(index=False), "reputation.csv", "text/csv", key=f"{key}_csv")


def provider_picker(key: str) -> list[str]:
    svc = state.reputation_service()
    ready = svc.available()
    labels = {p["name"]: f"{p['title']}" + ("" if p["ready"] else " (нет ключа)") for p in svc.status()}
    return st.multiselect("Сервисы", list(labels), default=ready, format_func=lambda n: labels[n], key=key)


def render() -> None:
    st.title("🌐 Репутация")
    svc = state.reputation_service()
    cols = st.columns(len(svc.status()))
    for col, p in zip(cols, svc.status(), strict=True):
        col.metric(p["title"], "готов" if p["ready"] else "нет ключа")
    if not any(p["key"] for p in svc.status()):
        st.info("Ключей API нет: доступны только сервисы без ключа. Как добавить ключи, описано на странице "
                "«Настройки» и в README.")

    if not policy_gate("rep_ack"):
        return

    providers = provider_picker("rep_providers")
    text = st.text_area("Индикаторы или любой текст с ними (можно defanged)", height=160, key="rep_input")
    found = [i for i in extract(text, allowlist=state.allowlist()) if i.type.value not in
             ("cve", "mitre", "path", "registry", "filename", "email")]
    external = [i for i in found if i.is_external]
    skipped = len(found) - len(external)
    st.caption(f"Распознано: {len(found)}, к отправке: {len(external)}"
               + (f", пропущено (внутренние/allowlist): {skipped}" if skipped else ""))
    c1, c2, c3 = st.columns([1, 1, 4])
    go = c1.button("Проверить", type="primary", disabled=not external or not providers)
    if c2.button("Очистить кеш"):
        st.toast(f"Удалено записей: {svc.cache.clear()}")
    c3.caption(f"Кеш: {svc.cache.stats()['fresh']} актуальных записей")
    if len(external) > 100:
        st.warning("Больше 100 индикаторов: будут проверены первые 100, чтобы не исчерпать лимиты.")
        external = external[:100]
    if go:
        st.session_state["rep_last"] = run_check(external, providers)
    results_view(st.session_state.get("rep_last", []), "rep_page")
