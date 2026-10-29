"""Черновик обоснования вердикта и причины эскалации по уликам из алерта.

Текст собирается из того, что действительно есть в алерте: время, хосты, пользователи,
признаки в командной строке (эвристики MITRE), последовательность событий, внешние
индикаторы и их репутация. Это заготовка: аналитик дописывает то, что проверил сам.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from ..alerts import AlertSummary
from ..alerts.parser import _collect, _flatten, mitre_hints
from ..ioc import IOCType, find_encoded
from ..reference import technique_name

# Что нужно от L2 в зависимости от категории
ESCALATION_NEEDS = {
    "ru": {
        "phishing": "проверить, кто ещё получил письмо, переходил ли пользователь по ссылке и вводил ли учётные "
                    "данные, удалить письма из ящиков и заблокировать отправителя",
        "malware": "изолировать хост, собрать артефакты (память, автозагрузка, задачи, службы), проанализировать "
                   "полезную нагрузку и проверить другие хосты на те же индикаторы",
        "bruteforce": "заблокировать источник, сбросить пароль скомпрометированной учётной записи и проверить "
                      "действия атакующего после входа",
        "lateral": "определить все затронутые хосты и учётные записи, изолировать их и найти точку входа",
        "credential_access": "сбросить учётные данные всех пользователей, входивших на хост, и проверить "
                             "их использование на других системах",
        "exfiltration": "оценить объём и состав переданных данных, заблокировать адрес назначения и подключить "
                        "ответственного за защиту данных",
        "ransomware": "немедленно изолировать хосты и сегменты сети и запустить процедуру реагирования на инцидент",
        "generic": "провести углублённый анализ хоста и учётной записи и определить масштаб инцидента",
    },
    "en": {
        "phishing": "identify other recipients, check whether the user clicked the link or entered credentials, "
                    "purge the emails and block the sender",
        "malware": "isolate the host, collect artifacts (memory, autoruns, tasks, services), analyse the payload "
                   "and hunt for the same indicators on other hosts",
        "bruteforce": "block the source, reset the compromised account password and review the attacker's actions "
                      "after the logon",
        "lateral": "identify all affected hosts and accounts, isolate them and find the initial access point",
        "credential_access": "reset credentials of all users who logged on to the host and check their use on "
                             "other systems",
        "exfiltration": "estimate the volume and content of transferred data, block the destination and involve "
                        "the data protection officer",
        "ransomware": "immediately isolate hosts and network segments and start the incident response procedure",
        "generic": "perform in-depth analysis of the host and account and determine the scope of the incident",
    },
}

T = {
    "ru": {
        "fired": "Правило «{name}» сработало{when}",
        "on_hosts": " на хосте {hosts}",
        "for_users": " для пользователя {users}",
        "signs": "В активности обнаружены признаки: {signs}.",
        "parent": "Процесс запущен из {parent}, что нетипично для легитимной работы.",
        "bruteforce_ok": "Зафиксировано {fail} неудачных входов (4625) и затем {ok} успешный вход (4624) с адреса "
                         "{src}: подбор пароля завершился успешно.",
        "bruteforce_fail": "Зафиксировано {fail} неудачных входов (4625) с адреса {src}; успешных входов нет.",
        "events": "Связанные события: {events}.",
        "decoded": "В раскодированной команде найдены индикаторы: {items}.",
        "decoded_cmd": "Закодированная команда после декодирования: `{cmd}`.",
        "rep_bad": "Репутация подтверждает вредоносность: {items}.",
        "rep_none": "Внешние индикаторы: {items} (репутацию стоит проверить).",
        "mitre": "Активность соответствует техникам MITRE ATT&CK: {items}.",
        "tp_end": "Совокупность признаков указывает на вредоносную активность, поэтому алерт классифицирован "
                  "как True Positive.",
        "fp_body": "Активность проверена и признана легитимной: [укажите подтверждение — плановая задача, "
                   "администратор, заявка на изменение, известное ПО]. ",
        "fp_rep_clean": "Внешние индикаторы ({items}) имеют чистую репутацию. ",
        "fp_no_ext": "Внешних индикаторов не обнаружено. ",
        "fp_end": "Признаков компрометации нет, поэтому алерт классифицирован как False Positive.",
        "esc": "Подтверждена вредоносная активность{where} (критичность: {sev}). Требуется эскалация на L2, чтобы "
               "{need}.",
        "esc_none": "не указана",
    },
    "en": {
        "fired": "Rule \"{name}\" fired{when}",
        "on_hosts": " on host {hosts}",
        "for_users": " for user {users}",
        "signs": "The activity shows the following signs: {signs}.",
        "parent": "The process was spawned by {parent}, which is atypical for legitimate use.",
        "bruteforce_ok": "{fail} failed logons (4625) followed by {ok} successful logon (4624) from {src} were "
                         "recorded: the brute force attempt succeeded.",
        "bruteforce_fail": "{fail} failed logons (4625) from {src} were recorded; no successful logons.",
        "events": "Related events: {events}.",
        "decoded": "Indicators found in the decoded command: {items}.",
        "decoded_cmd": "The encoded command decodes to: `{cmd}`.",
        "rep_bad": "Reputation confirms maliciousness: {items}.",
        "rep_none": "External indicators: {items} (reputation should be checked).",
        "mitre": "The activity maps to MITRE ATT&CK techniques: {items}.",
        "tp_end": "Taken together, the evidence indicates malicious activity, so the alert is classified as "
                  "True Positive.",
        "fp_body": "The activity was reviewed and found legitimate: [state the confirmation — scheduled task, "
                   "administrator, change request, known software]. ",
        "fp_rep_clean": "External indicators ({items}) have a clean reputation. ",
        "fp_no_ext": "No external indicators were found. ",
        "fp_end": "There are no signs of compromise, so the alert is classified as False Positive.",
        "esc": "Malicious activity is confirmed{where} (severity: {sev}). Escalation to L2 is required to {need}.",
        "esc_none": "not specified",
    },
}

OFFICE = ("winword", "excel", "powerpnt", "outlook", "onenote", "mshta", "wscript", "cscript")
BAD = ("malicious", "suspicious")


def _short(values: list[str], limit: int = 3) -> str:
    return ", ".join(values[:limit]) + (f" (+{len(values) - limit})" if len(values) > limit else "")


def _when(a: AlertSummary, lang: str) -> str:
    if not a.first_seen:
        return ""
    if lang == "ru":
        return f" {a.first_seen}"
    return f" at {a.first_seen}"


def _collect_all_event_ids(a: AlertSummary) -> list[str]:
    if a.raw is None:
        return a.event_ids
    out: list[str] = []
    for path, value in _flatten(a.raw):
        if _collect([(path, value)], "event_id"):
            out.append(str(value))
    return out


def draft_reason(a: AlertSummary, verdict: str, lang: str = "ru",
                 reputation: dict[str, str] | None = None) -> str:
    """Черновик раздела «Reason for Classifying as TP/FP»."""
    lang = lang if lang in T else "ru"
    t = T[lang]
    reputation = reputation or {}
    external = [i for i in a.iocs if i.is_external and i.type not in (IOCType.FILENAME,)]
    ext_names = [i.defanged for i in external]

    if verdict.upper() == "FP":
        clean = [i.defanged for i in external if reputation.get(i.value) == "clean"]
        text = t["fp_body"]
        if clean and len(clean) == len(external):
            text += t["fp_rep_clean"].format(items=_short(clean))
        elif not external:
            text += t["fp_no_ext"]
        return text + t["fp_end"]

    parts = []
    head = t["fired"].format(name=a.name or "?", when=_when(a, lang))
    if a.hosts:
        head += t["on_hosts"].format(hosts=_short(a.hosts))
    if a.users:
        head += t["for_users"].format(users=_short(a.users))
    parts.append(head + ".")

    # Признаки ищем по всему алерту, даже если техника уже указана в нём явно
    blob = json.dumps(a.raw, ensure_ascii=False) if a.raw is not None else " ".join(a.commands)
    signs = [reason for rx, _, reason in mitre_hints() if rx.search(blob)]
    if signs and lang == "ru":
        parts.append(t["signs"].format(signs="; ".join(dict.fromkeys(signs)).lower()))

    parents = [p for p in a.parent_processes if any(o in p.lower() for o in OFFICE)]
    if parents:
        parts.append(t["parent"].format(parent=parents[0].replace("\\\\", "\\").split("\\")[-1]))

    # Считаем каждое вхождение EventID (в списке a.event_ids значения уникальны)
    counts = Counter(_collect_all_event_ids(a))
    if counts.get("4625"):
        src = _short(a.src_ips) or "?"
        key = "bruteforce_ok" if counts.get("4624") else "bruteforce_fail"
        parts.append(t[key].format(fail=counts["4625"], ok=counts.get("4624", 0), src=src))
    elif a.event_ids:
        parts.append(t["events"].format(events=", ".join(dict.fromkeys(a.event_ids))))

    for cmd in a.commands:
        blobs = [b for b in find_encoded(cmd) if b.kind == "powershell"]
        if blobs:
            text = re.sub(r"\s+", " ", blobs[0].decoded).strip()
            parts.append(t["decoded_cmd"].format(cmd=text[:200] + ("…" if len(text) > 200 else "")))
            break

    decoded = [i.defanged for i in a.iocs if "decoded" in i.tags and i.type in (IOCType.URL, IOCType.IPV4,
                                                                                  IOCType.DOMAIN)]
    if decoded:
        parts.append(t["decoded"].format(items=_short(decoded)))

    bad = [f"{i.defanged} ({reputation[i.value]})" for i in external if reputation.get(i.value) in BAD]
    if bad:
        parts.append(t["rep_bad"].format(items=_short(bad)))
    elif ext_names:
        parts.append(t["rep_none"].format(items=_short(ext_names)))

    if a.mitre:
        items = [f"{h.technique} {technique_name(h.technique)}".strip() for h in a.mitre]
        parts.append(t["mitre"].format(items="; ".join(items[:5])))

    parts.append(t["tp_end"])
    return " ".join(parts)


def draft_escalation(a: AlertSummary, category: str, lang: str = "ru") -> str:
    """Черновик раздела «Reason for Escalating the Alert»."""
    lang = lang if lang in T else "ru"
    t = T[lang]
    needs = ESCALATION_NEEDS[lang]
    targets = a.hosts + [u for u in a.users if u not in a.hosts]
    if lang == "ru":
        where = f" на {_short(targets)}" if targets else ""
    else:
        where = f" on {_short(targets)}" if targets else ""
    return t["esc"].format(where=where, sev=a.severity or t["esc_none"], need=needs.get(category, needs["generic"]))
