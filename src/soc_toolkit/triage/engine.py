"""Оценка алерта: рекомендуемый вердикт (TP/FP), уверенность, нужна ли эскалация и почему.

Логика прозрачная: каждый найденный признак даёт вес (+ за True Positive, − за False Positive),
сумма определяет вердикт. Признаки из signals.yaml (регулярные выражения) дополняются
структурными: цепочка 4625→4624, офисный родитель у оболочки, репутация, решение из SIEM,
исход (заблокировано / выполнено). Эскалация решается по исходу, категории, критичности
и привилегиям затронутых учётных записей. Это рекомендация L1, решение остаётся за аналитиком.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..alerts import AlertSummary
from ..alerts.parser import _collect, _flatten, _key_of
from ..ioc import IOCType, find_encoded

HERE = Path(__file__).resolve().parent

TP_THRESHOLD = 3          # сумма весов, начиная с которой алерт считается True Positive
HIGH_IMPACT = {"credential_access", "ransomware", "lateral", "exfiltration"}
OFFICE = ("winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "acrord32", "acrobat")
SHELLS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil",
          "bitsadmin", "msiexec", "wmic", "schtasks", "bash", "sh")
PRIVILEGED = re.compile(r"(^|\\|\b)(administrator|admin|adm[_-]|root|domain admins|enterprise admins|da[_-])|"
                        r"(_adm|-adm|\.adm)$", re.I)
BLOCKED = re.compile(r"block|denied|deny|prevent|quarantin|delete|remov|clean|remediat|drop|reject|stopp|killed|"
                     r"terminat|not executed|failure|failed|заблок|удал|карантин|запрещ", re.I)
SUCCEEDED = re.compile(r"allow|permit|success|executed|delivered|accepted|detected only|audit|passed|"
                       r"clicked|разреш|успеш|доставл", re.I)
DISP_TP = re.compile(r"true.?positive|truepositive|malicious|compromis|confirmed", re.I)
DISP_FP = re.compile(r"false.?positive|falsepositive|benign|not.?malicious|expected|legit|ложн", re.I)


@lru_cache
def signals() -> list[dict[str, Any]]:
    data = yaml.safe_load((HERE / "signals.yaml").read_text(encoding="utf-8"))
    for s in data:
        s["rx"] = re.compile(s["pattern"], re.I | re.S)
        s.setdefault("where", "evidence")
        s.setdefault("exec", False)
    return data


@dataclass
class Factor:
    id: str
    weight: int
    ru: str
    en: str
    exec: bool = False          # говорит о реальном выполнении/успехе атаки
    category: str = ""

    def text(self, lang: str) -> str:
        return self.ru if lang == "ru" else self.en


@dataclass
class Assessment:
    verdict: str                     # TP / FP
    certain: bool                    # False: признаков мало, нужна ручная проверка
    confidence: int                  # 0-100
    score: int
    category: str
    escalate: bool
    outcome: str                     # blocked / succeeded / unknown
    factors: list[Factor] = field(default_factory=list)
    escalation_why: dict[str, str] = field(default_factory=dict)   # lang -> текст
    impact: list[Factor] = field(default_factory=list)            # контекст без веса: привилегии, хосты

    @property
    def tp_factors(self) -> list[Factor]:
        return sorted((f for f in self.factors if f.weight > 0), key=lambda f: -f.weight)

    @property
    def fp_factors(self) -> list[Factor]:
        return sorted((f for f in self.factors if f.weight < 0), key=lambda f: f.weight)

    @property
    def executed(self) -> bool:
        return any(f.exec for f in self.factors if f.weight > 0) or self.outcome == "succeeded"

    def label(self, lang: str = "ru") -> str:
        if not self.certain:
            return "Требует проверки (склоняюсь к TP)" if lang == "ru" else "Needs review (leaning TP)"
        return "True Positive" if self.verdict == "TP" else "False Positive"


# --- Тексты ---------------------------------------------------------------------------------

def _defang(v: str) -> str:
    return v.replace("http", "hxxp").replace(".", "[.]") if v else v


def _short(values: list[str], limit: int = 3) -> str:
    return ", ".join(values[:limit]) + (f" (+{len(values) - limit})" if len(values) > limit else "")


def _basename(p: str) -> str:
    return re.split(r"[\\/]", p.replace("\\\\", "\\"))[-1]


# --- Сбор текста для поиска признаков -------------------------------------------------------

def decoded_commands(a: AlertSummary) -> list[str]:
    out: list[str] = []
    for cmd in a.commands:
        out.extend(b.decoded for b in find_encoded(cmd) if b.kind == "powershell")
    return out


def _texts(a: AlertSummary) -> dict[str, str]:
    flat = _flatten(a.raw) if a.raw is not None else []
    rule_text = {a.name, a.description}
    evidence_lines = []
    for path, v in flat:
        if v is None or isinstance(v, bool):
            continue
        sv = str(v)
        if sv in rule_text:
            continue
        evidence_lines.append(f"{_key_of(path)[0]}={sv}")
    decoded = decoded_commands(a)
    commands = "\n".join(a.commands + decoded)
    return {
        "evidence": "\n".join(evidence_lines + decoded),
        "commands": commands,
        "processes": "\n".join(a.processes + a.parent_processes) + "\n" + commands,
        "name": f"{a.name}\n{a.description}",
        "all": "\n".join(evidence_lines + decoded + [a.name, a.description]),
    }


def _token(text: str, start: int, end: int) -> str:
    """Расширить совпадение до целого слова или пути: \\ccm\\ -> C:\\Windows\\CCM\\CcmExec.exe."""
    stop = " \t\n\"'=,;()[]{}<>"
    while start > 0 and text[start - 1] not in stop and end - start < 80:
        start -= 1
    while end < len(text) and text[end] not in stop and end - start < 80:
        end += 1
    return text[start:end]


def _event_counts(a: AlertSummary) -> Counter[str]:
    if a.raw is None:
        return Counter(a.event_ids)
    out: Counter[str] = Counter()
    for path, value in _flatten(a.raw):
        if _collect([(path, value)], "event_id"):
            out[str(value)] += 1
    return out


# --- Оценка ---------------------------------------------------------------------------------

def assess(a: AlertSummary, reputation: dict[str, str] | None = None) -> Assessment:
    """Оценить алерт. reputation: значение IOC -> malicious/suspicious/clean/unknown."""
    reputation = reputation or {}
    texts = _texts(a)
    factors: list[Factor] = []

    for s in signals():
        m = s["rx"].search(texts[s["where"]])
        if m:
            # Найденный фрагмент делает текст конкретным: «найдено: CcmExec.exe»
            frag = re.sub(r"\s+", " ", _token(texts[s["where"]], m.start(), m.end())).strip(" =\"'")
            frag = frag if len(frag) <= 60 else frag[:57] + "…"
            factors.append(Factor(s["id"], int(s["weight"]), f"{s['ru']} (найдено: «{frag}»)",
                                  f"{s['en']} (found: \"{frag}\")", bool(s["exec"]), s.get("category", "")))

    factors.extend(_structural(a, reputation))
    outcome = _outcome(a, factors)
    if outcome == "blocked":
        tool = _short(a.outcomes, 2)
        factors.append(Factor("blocked", 0, f"средство защиты остановило активность (действие: {tool})",
                              f"the security control stopped the activity (action: {tool})"))
    elif outcome == "succeeded" and a.outcomes:
        tool = _short(a.outcomes, 2)
        factors.append(Factor("allowed", 1, f"активность не была заблокирована (действие: {tool})",
                              f"the activity was not blocked (action: {tool})", exec=True))

    if not any(f.weight > 0 for f in factors):
        factors.append(Factor("nothing", -1, "явных признаков вредоносной активности в данных алерта нет",
                              "the alert data shows no clear signs of malicious activity"))

    score = sum(f.weight for f in factors)
    disposition = next((f for f in factors if f.id.startswith("siem_")), None)
    if disposition:
        verdict, certain, confidence = ("TP" if disposition.weight > 0 else "FP"), True, 95
    elif score >= TP_THRESHOLD:
        verdict, certain, confidence = "TP", True, min(97, 60 + score * 4)
    elif score <= 0:
        verdict, certain = "FP", True
        confidence = min(90, 55 + abs(score) * 8)
    else:
        verdict, certain, confidence = "TP", False, 45 + score * 5

    category = guess_category(a, factors)
    impact = _impact(a)
    a_ = Assessment(verdict, certain, confidence, score, category, False, outcome, factors, {}, impact)
    a_.escalate, a_.escalation_why = _escalation(a, a_)
    return a_


def _structural(a: AlertSummary, reputation: dict[str, str]) -> list[Factor]:
    out: list[Factor] = []

    # Решение, уже принятое в SIEM/EDR
    for d in a.dispositions:
        if DISP_FP.search(d):
            out.append(Factor("siem_fp", -6, f"в SIEM/EDR алерт уже классифицирован как «{d}»",
                              f"the SIEM/EDR already classified the alert as \"{d}\""))
            break
        if DISP_TP.search(d):
            out.append(Factor("siem_tp", 6, f"в SIEM/EDR алерт уже классифицирован как «{d}»",
                              f"the SIEM/EDR already classified the alert as \"{d}\"", exec=True))
            break

    # Оболочка или скрипт, запущенные офисным приложением
    parents = [p for p in a.parent_processes if any(o in p.lower() for o in OFFICE)]
    procs = " ".join(a.processes + a.commands).lower()
    if parents and any(s in procs for s in SHELLS):
        parent = _basename(parents[0])
        child = next((_basename(p) for p in a.processes if any(s in p.lower() for s in SHELLS)), "командная оболочка")
        out.append(Factor("office_child", 4, f"{child} запущен из {parent}: документ запустил код, для офисного "
                                             "приложения это нетипично",
                          f"{child} was spawned by {parent}: a document launched code, atypical for an "
                          "office application", exec=True, category="malware"))

    # Подбор пароля по журналам Windows
    counts = _event_counts(a)
    fails, ok = counts.get("4625", 0) + counts.get("4771", 0), counts.get("4624", 0)
    src = _short(a.src_ips) or "?"
    if fails:
        if ok:
            out.append(Factor("bruteforce_success", 5,
                              f"{fails} неудачных входов (4625), затем {ok} успешный (4624) с адреса {src}: "
                              "пароль подобран, атакующий вошёл в систему",
                              f"{fails} failed logons (4625) followed by {ok} successful logon (4624) from {src}: "
                              "the password was guessed and the attacker logged on", exec=True,
                              category="bruteforce"))
        elif fails >= 5:
            out.append(Factor("bruteforce", 3 if fails >= 10 else 2,
                              f"{fails} неудачных входов (4625) с адреса {src}, успешных входов нет",
                              f"{fails} failed logons (4625) from {src}, no successful logons",
                              category="bruteforce"))
        else:
            out.append(Factor("few_fails", -1, f"всего {fails} неудачных входа: похоже на ошибку ввода пароля",
                              f"only {fails} failed logons: looks like a mistyped password"))

    # Вход из интернета
    public_src = [i.value for i in a.iocs if i.type == IOCType.IPV4 and i.scope == "public" and i.value in a.src_ips]
    if ok and public_src:
        out.append(Factor("external_logon", 2, f"успешный вход с внешнего адреса {_short(public_src)}",
                          f"successful logon from an external address {_short(public_src)}", exec=True))

    # Индикаторы, спрятанные в закодированной команде
    decoded = [i.defanged for i in a.iocs if "decoded" in i.tags and i.is_external
               and i.type in (IOCType.URL, IOCType.IPV4, IOCType.DOMAIN)]
    if decoded:
        out.append(Factor("decoded_ioc", 2, f"в раскодированной команде внешние адреса: {_short(decoded)}",
                          f"the decoded command contains external addresses: {_short(decoded)}"))

    # Репутация внешних индикаторов
    external = [i for i in a.iocs if i.is_external and i.type != IOCType.FILENAME]
    bad = [f"{i.defanged} ({reputation[i.value]})" for i in external if reputation.get(i.value) == "malicious"]
    sus = [f"{i.defanged}" for i in external if reputation.get(i.value) == "suspicious"]
    checked = [i for i in external if reputation.get(i.value) in ("malicious", "suspicious", "clean")]
    if bad:
        out.append(Factor("rep_malicious", 4, f"репутационные сервисы считают вредоносными: {_short(bad)}",
                          f"reputation services flag as malicious: {_short(bad)}"))
    elif sus:
        out.append(Factor("rep_suspicious", 2, f"подозрительная репутация: {_short(sus)}",
                          f"suspicious reputation: {_short(sus)}"))
    elif checked and len(checked) == len(external):
        clean = [i.defanged for i in checked]
        out.append(Factor("rep_clean", -2, f"все внешние индикаторы имеют чистую репутацию: {_short(clean)}",
                          f"all external indicators have a clean reputation: {_short(clean)}"))
    return out


def _outcome(a: AlertSummary, factors: list[Factor]) -> str:
    if any(f.id in ("bruteforce_success", "link_clicked", "credentials_submitted") for f in factors):
        return "succeeded"
    if any(f.id == "bruteforce" for f in factors):
        return "blocked"
    text = " ".join(a.outcomes)
    if not text:
        return "unknown"
    if BLOCKED.search(text):
        return "blocked"
    if SUCCEEDED.search(text):
        return "succeeded"
    return "unknown"


def _impact(a: AlertSummary) -> list[Factor]:
    out = []
    priv = [u for u in a.users if PRIVILEGED.search(u.split("\\")[-1].split("@")[0]) or "admin" in u.lower()]
    if priv:
        out.append(Factor("privileged", 0, f"затронута привилегированная учётная запись {_short(priv)}",
                          f"a privileged account is involved: {_short(priv)}"))
    servers = [h for h in a.hosts if re.search(r"(^|[-_.])(dc|srv|sql|db|exch|fs|adfs|ca|sccm|vcenter|esx)", h, re.I)]
    if servers:
        out.append(Factor("server", 0, f"затронут сервер {_short(servers)}",
                          f"a server is affected: {_short(servers)}"))
    if len(a.hosts) > 1:
        out.append(Factor("multi_host", 0, f"затронуто несколько хостов ({len(a.hosts)})",
                          f"several hosts are affected ({len(a.hosts)})"))
    if a.severity in ("high", "critical"):
        out.append(Factor("severity", 0, f"критичность правила в SIEM: {a.severity}",
                          f"rule severity in the SIEM: {a.severity}"))
    return out


CATEGORY_BY_TECHNIQUE = [
    ({"T1486", "T1490"}, "ransomware"), ({"T1003", "T1558"}, "credential_access"), ({"T1110"}, "bruteforce"),
    ({"T1566"}, "phishing"), ({"T1021", "T1570"}, "lateral"), ({"T1041", "T1567"}, "exfiltration"),
    ({"T1059", "T1204", "T1105", "T1218"}, "malware"),
]


def guess_category(a: AlertSummary, factors: list[Factor] | None = None) -> str:
    votes: Counter[str] = Counter()
    for f in factors or []:
        if f.category and f.weight > 0:
            votes[f.category] += f.weight
    if votes:
        # Тяжёлые категории важнее: шифровальщик с PowerShell всё равно шифровальщик
        for heavy in ("ransomware", "credential_access", "exfiltration"):
            if votes.get(heavy, 0) >= 4:
                return heavy
        return votes.most_common(1)[0][0]
    ids = {h.technique.split(".")[0] for h in a.mitre}
    for techniques, cat in CATEGORY_BY_TECHNIQUE:
        if ids & techniques:
            return cat
    return "generic"


# --- Эскалация ------------------------------------------------------------------------------

NEEDS = {
    "ru": {
        "phishing": "проверить, кто ещё получил письмо, вводил ли пользователь учётные данные, и удалить письма "
                    "из всех ящиков",
        "malware": "изолировать хост, собрать артефакты и проверить, не распространилась ли угроза",
        "bruteforce": "сбросить пароль учётной записи и проверить действия атакующего после входа",
        "lateral": "определить все затронутые хосты и учётные записи и найти точку входа",
        "credential_access": "сбросить учётные данные всех пользователей, входивших на хост, и проверить их "
                             "использование на других системах",
        "exfiltration": "оценить объём и состав переданных данных и подключить ответственного за защиту данных",
        "ransomware": "немедленно изолировать хосты и сегменты сети и запустить процедуру реагирования на инцидент",
        "generic": "провести углублённый анализ хоста и учётной записи и определить масштаб инцидента",
    },
    "en": {
        "phishing": "identify other recipients, check whether credentials were entered and purge the emails",
        "malware": "isolate the host, collect artifacts and check whether the threat has spread",
        "bruteforce": "reset the account password and review the attacker's actions after the logon",
        "lateral": "identify all affected hosts and accounts and find the initial access point",
        "credential_access": "reset credentials of all users who logged on to the host and check their use "
                             "on other systems",
        "exfiltration": "estimate the volume and content of transferred data and involve the data protection "
                        "officer",
        "ransomware": "immediately isolate hosts and network segments and start the incident response procedure",
        "generic": "perform in-depth analysis of the host and account and determine the scope of the incident",
    },
}


def _escalation(a: AlertSummary, x: Assessment) -> tuple[bool, dict[str, str]]:
    where = _short(a.hosts + [u for u in a.users if u not in a.hosts]) or "?"
    ctx_ru = "; ".join(f.ru for f in x.impact)
    ctx_en = "; ".join(f.en for f in x.impact)

    def text(ru: str, en: str) -> dict[str, str]:
        return {"ru": ru, "en": en}

    if x.verdict == "FP" and x.certain:
        main = x.fp_factors[0] if x.fp_factors else None
        return False, text(
            "Эскалация не требуется: активность признана легитимной" + (f" ({main.ru})" if main else "") +
            ". Алерт закрывается на L1; при повторении стоит настроить исключение в правиле.",
            "Escalation is not required: the activity is legitimate" + (f" ({main.en})" if main else "") +
            ". The alert is closed at L1; if it recurs, consider tuning the rule with an exclusion.")

    if not x.certain:
        return True, text(
            f"Данных в алерте недостаточно, чтобы уверенно подтвердить или исключить атаку на {where}. "
            f"Требуется эскалация на L2 для проверки: {NEEDS['ru'][x.category]}.",
            f"The alert data is not enough to confirm or rule out an attack on {where}. "
            f"Escalation to L2 is required to verify: {NEEDS['en'][x.category]}.")

    high_impact = x.category in HIGH_IMPACT
    critical = a.severity == "critical"
    privileged = any(f.id in ("privileged", "server") for f in x.impact)
    if not x.executed and not high_impact and not critical and not (privileged and x.outcome != "blocked"):
        if x.outcome == "blocked":
            why_ru = "активность была остановлена средством защиты, признаков успешного выполнения нет"
            why_en = "the activity was stopped by a security control and there are no signs of successful execution"
        else:
            why_ru = "атака не достигла цели: признаков выполнения кода, входа в систему или перехода по ссылке нет"
            why_en = ("the attack did not reach its goal: there are no signs of code execution, logon or a clicked "
                      "link")
        return False, text(
            f"Эскалация не требуется: {why_ru}. L1 закрывает алерт после выполнения рекомендаций ниже "
            "(блокировка индикаторов, уведомление пользователя).",
            f"Escalation is not required: {why_en}. L1 closes the alert after the remediation steps below "
            "(blocking indicators, notifying the user).")

    reasons_ru, reasons_en = [], []
    if x.executed:
        ids = {f.id for f in x.factors if f.weight > 0}
        if ids & {"bruteforce_success", "external_logon"}:
            reasons_ru.append("атакующий успешно вошёл в систему")
            reasons_en.append("the attacker successfully logged on")
        elif ids & {"link_clicked", "credentials_submitted"}:
            reasons_ru.append("пользователь перешёл по ссылке из письма, учётные данные могли быть скомпрометированы")
            reasons_en.append("the user clicked the link in the email, credentials may be compromised")
        elif x.outcome == "blocked":
            reasons_ru.append("средство защиты сработало, но вредоносный код успел выполниться на хосте")
            reasons_en.append("the security control fired, but malicious code had already run on the host")
        else:
            reasons_ru.append("вредоносный код выполнился на хосте и не был остановлен")
            reasons_en.append("malicious code ran on the host and was not stopped")
    if high_impact:
        reasons_ru.append(f"категория «{x.category}» требует расследования масштаба")
        reasons_en.append(f"the \"{x.category}\" category requires a scope investigation")
    if ctx_ru:
        reasons_ru.append(ctx_ru)
        reasons_en.append(ctx_en)
    return True, text(
        f"Подтверждена вредоносная активность на {where}: " + "; ".join(reasons_ru) +
        f". Требуется эскалация на L2, чтобы {NEEDS['ru'][x.category]}.",
        f"Malicious activity is confirmed on {where}: " + "; ".join(reasons_en) +
        f". Escalation to L2 is required to {NEEDS['en'][x.category]}.")


# --- Рекомендации под конкретный алерт ------------------------------------------------------

def specific_remediation(a: AlertSummary, x: Assessment, lang: str = "ru",
                         reputation: dict[str, str] | None = None) -> list[str]:
    """Конкретные действия с именами хостов, учётных записей и индикаторов из алерта."""
    reputation = reputation or {}
    ru = lang == "ru"
    out: list[str] = []
    if x.verdict == "FP" and x.certain:
        main = x.fp_factors[0] if x.fp_factors else None
        if main and main.id in ("mgmt_tool", "scanner", "backup_update"):
            chain = [_basename(p) for p in a.parent_processes[:1] + a.processes[:1]]
            what = " → ".join(chain) if chain else _short(a.src_ips or a.hosts, 1)
            out.append(f"Добавить в правило узкое исключение для {what} (с учётом пути и подписи), сохранив "
                       "контроль остальных запусков" if ru else
                       f"Add a narrow rule exclusion for {what} (path and signature based) while keeping coverage "
                       "for other executions")
            out.append("Согласовать исключение с владельцем системы управления и зафиксировать в базе знаний SOC"
                       if ru else "Agree the exclusion with the management system owner and record it in the SOC "
                       "knowledge base")
        return out
    external = [i for i in a.iocs if i.is_external and i.type in (IOCType.IPV4, IOCType.DOMAIN, IOCType.URL)]
    if external:
        vals = _short([i.defanged for i in external], 4)
        out.append(f"Заблокировать на МСЭ, прокси и DNS: {vals}" if ru else f"Block on firewall, proxy and DNS: {vals}")
    hashes = [i.value for i in a.iocs if i.type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5)]
    if hashes and x.category in ("malware", "ransomware", "phishing"):
        out.append(f"Добавить хэш {hashes[0][:16]}… в блок-лист EDR и проверить его на других хостах" if ru else
                   f"Add hash {hashes[0][:16]}… to the EDR blocklist and hunt for it on other hosts")
    if a.hosts and (x.executed or x.category in HIGH_IMPACT):
        out.append(f"Изолировать хост {_short(a.hosts, 2)} средствами EDR до окончания расследования" if ru else
                   f"Isolate host {_short(a.hosts, 2)} via EDR until the investigation is complete")
    users = [u for u in a.users if "@" not in u or x.category != "phishing"] or a.users
    if users and (x.category in ("bruteforce", "credential_access", "phishing", "lateral") and x.executed):
        out.append(f"Сбросить пароль и завершить сессии учётной записи {_short(users, 2)}, включить MFA" if ru else
                   f"Reset the password and revoke sessions for {_short(users, 2)}, enforce MFA")
    if any(f.id == "persistence" for f in x.factors):
        out.append("Удалить созданную задачу, службу или ключ автозапуска" if ru else
                   "Remove the created scheduled task, service or autorun key")
    return out
