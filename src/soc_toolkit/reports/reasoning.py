"""Тексты разделов отчёта «Reason for Classifying» и «Reason for Escalating» по оценке алерта.

Текст строится из того, что действительно есть в алерте и что нашёл движок оценки (triage):
кто, где и когда, признаки за и против, раскодированная команда, репутация, техники MITRE
и вывод. Если аналитик выбрал вердикт, отличный от рекомендации, текст строится под его выбор,
а место для подтверждения помечается квадратными скобками.
"""

from __future__ import annotations

import re

from ..alerts import AlertSummary
from ..ioc import IOCType
from ..reference import technique_name
from ..triage import Assessment, assess
from ..triage.engine import NEEDS, decoded_commands

NET = (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6)

T = {
    "ru": {
        "fired": "Правило «{name}» сработало{when}",
        "on_hosts": " на хосте {hosts}",
        "for_users": " для пользователя {users}",
        "tp_signs": "Признаки вредоносной активности:",
        "fp_signs": "Признаки легитимной активности:",
        "against": "Против этого вывода говорит:",
        "explained": "Сработавшие признаки объясняются легитимной работой:",
        "decoded_cmd": "Закодированная команда после декодирования: `{cmd}`.",
        "mitre": "Техники MITRE ATT&CK: {items}.",
        "ext": "Внешние индикаторы: {items} (репутация не проверялась, проверьте на вкладке «Индикаторы и "
               "репутация»).",
        "blocked": "Средство защиты заблокировало активность ({action}).",
        "tp_end": "Вывод: совокупность признаков указывает на вредоносную активность, поэтому алерт классифицирован "
                  "как True Positive.",
        "tp_unsure": "Вывод: признаков недостаточно, чтобы уверенно исключить атаку, поэтому алерт классифицирован "
                     "как True Positive до проверки на L2.",
        "tp_manual": "[Укажите, что подтвердило вредоносность: результаты проверки хоста, ответ пользователя, "
                     "дополнительные события.]",
        "fp_manual": "[Укажите подтверждение легитимности: плановая задача, действия администратора, заявка на "
                     "изменение, известное ПО.]",
        "fp_none": "Признаков компрометации не обнаружено: нет выполнения закодированных команд, загрузки файлов из "
                   "интернета, обращений к вредоносным адресам и успешного входа атакующего.",
        "no_ext": "Обращений к внешним адресам в алерте нет.",
        "fp_end": "Вывод: активность легитимна, поэтому алерт классифицирован как False Positive.",
        "esc_forced": "Аналитик принял решение об эскалации{where}. Требуется эскалация на L2, чтобы {need}.",
        "no_esc_forced": "Эскалация не требуется: по результатам проверки аналитика угроза устранена на L1.",
    },
    "en": {
        "fired": "Rule \"{name}\" fired{when}",
        "on_hosts": " on host {hosts}",
        "for_users": " for user {users}",
        "tp_signs": "Signs of malicious activity:",
        "fp_signs": "Signs of legitimate activity:",
        "against": "Evidence against this conclusion:",
        "explained": "The triggered signs are explained by legitimate activity:",
        "decoded_cmd": "The encoded command decodes to: `{cmd}`.",
        "mitre": "MITRE ATT&CK techniques: {items}.",
        "ext": "External indicators: {items} (reputation not checked yet).",
        "blocked": "The security control blocked the activity ({action}).",
        "tp_end": "Conclusion: taken together, the evidence indicates malicious activity, so the alert is classified "
                  "as True Positive.",
        "tp_unsure": "Conclusion: the evidence is not enough to rule out an attack, so the alert is classified as "
                     "True Positive pending L2 review.",
        "tp_manual": "[State what confirmed maliciousness: host review results, user response, additional events.]",
        "fp_manual": "[State the confirmation of legitimacy: scheduled task, administrator action, change request, "
                     "known software.]",
        "fp_none": "No signs of compromise were found: no encoded commands, no downloads from the internet, no "
                   "connections to malicious addresses and no successful attacker logon.",
        "no_ext": "The alert contains no connections to external addresses.",
        "fp_end": "Conclusion: the activity is legitimate, so the alert is classified as False Positive.",
        "esc_forced": "The analyst decided to escalate{where}. Escalation to L2 is required to {need}.",
        "no_esc_forced": "Escalation is not required: according to the analyst's review the threat was resolved "
                         "at L1.",
    },
}


def _short(values: list[str], limit: int = 3) -> str:
    return ", ".join(values[:limit]) + (f" (+{len(values) - limit})" if len(values) > limit else "")


def _head(a: AlertSummary, t: dict[str, str], lang: str) -> str:
    when = (f" {a.first_seen}" if lang == "ru" else f" at {a.first_seen}") if a.first_seen else ""
    head = t["fired"].format(name=a.name or "?", when=when)
    if a.hosts:
        head += t["on_hosts"].format(hosts=_short(a.hosts))
    if a.users:
        head += t["for_users"].format(users=_short(a.users))
    return head + "."


def _cap(line: str) -> str:
    # Имя файла или команды в начале строки оставляем как есть: powershell.exe, 8 неудачных входов
    first = line.split(" ", 1)[0]
    return line if "." in first or any(c.isdigit() for c in first) else line[:1].upper() + line[1:]


def _bullets(title: str, lines: list[str]) -> str:
    return title + "\n" + "\n".join(f"- {_cap(ln)}" for ln in lines)


def draft_reason(a: AlertSummary, verdict: str, lang: str = "ru", reputation: dict[str, str] | None = None,
                 assessment: Assessment | None = None) -> str:
    """Текст раздела «Reason for Classifying as TP/FP»."""
    lang = lang if lang in T else "ru"
    t = T[lang]
    x = assessment or assess(a, reputation)
    tp = [f.text(lang) for f in x.tp_factors]
    real_fp = [f.text(lang) for f in x.fp_factors if f.id != "nothing"]
    blocks = [_head(a, t, lang)]

    if verdict.upper() == "FP":
        if real_fp:
            blocks.append(_bullets(t["fp_signs"], real_fp))
        if tp:
            blocks.append(_bullets(t["explained"], tp))
        if x.verdict != "FP" or not x.certain:
            blocks.append(t["fp_manual"])
        elif not tp:
            blocks.append(t["fp_none"])
        if not any(i.is_external for i in a.iocs if i.type in NET):
            blocks.append(t["no_ext"])
        blocks.append(t["fp_end"])
        return "\n\n".join(blocks)

    if tp:
        blocks.append(_bullets(t["tp_signs"], tp))
    cmds = decoded_commands(a)
    if cmds:
        text = re.sub(r"\s+", " ", cmds[0]).strip()
        blocks.append(t["decoded_cmd"].format(cmd=text[:200] + ("…" if len(text) > 200 else "")))
    unchecked = [i.defanged for i in a.iocs if i.is_external and i.type in (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4)
                 and (reputation or {}).get(i.value) in (None, "", "unknown")]
    if unchecked:
        blocks.append(t["ext"].format(items=_short(unchecked, 4)))
    if x.outcome == "blocked" and a.outcomes:
        blocks.append(t["blocked"].format(action=_short(a.outcomes, 2)))
    if a.mitre:
        items = [f"{h.technique} {technique_name(h.technique)}".strip() for h in a.mitre]
        blocks.append(t["mitre"].format(items="; ".join(items[:5])))
    if real_fp:
        blocks.append(_bullets(t["against"], real_fp))
    if x.verdict == "FP" and x.certain:
        blocks.append(t["tp_manual"])
    blocks.append(t["tp_end"] if x.certain or x.verdict == "FP" else t["tp_unsure"])
    return "\n\n".join(blocks)


def draft_escalation(a: AlertSummary, category: str, lang: str = "ru", escalate: bool | None = None,
                     reputation: dict[str, str] | None = None, assessment: Assessment | None = None) -> str:
    """Текст раздела «Reason for Escalating the Alert».

    escalate=None: взять решение движка. Если аналитик решил иначе, текст строится под его решение.
    """
    lang = lang if lang in T else "ru"
    t = T[lang]
    x = assessment or assess(a, reputation)
    if escalate is None or escalate == x.escalate:
        return x.escalation_why[lang]
    if escalate:
        targets = a.hosts + [u for u in a.users if u not in a.hosts]
        where = (f" по {_short(targets)}" if lang == "ru" else f" for {_short(targets)}") if targets else ""
        need = NEEDS[lang].get(category, NEEDS[lang]["generic"])
        return t["esc_forced"].format(where=where, need=need)
    return t["no_esc_forced"]
