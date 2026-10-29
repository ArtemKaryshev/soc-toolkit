"""Разбор JSON алерта (Splunk, KUMA, Elastic, Defender, произвольный формат).

Алерт превращается в AlertSummary: название, критичность, время, хосты, пользователи,
IP, процессы, командные строки, файлы, хэши, IOC, подсказки MITRE и таймлайн
вложенных событий. Сопоставление полей описано в field_map.yaml.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..ioc import IOC, Allowlist, extract

HERE = Path(__file__).resolve().parent


@lru_cache
def field_map() -> dict[str, list[str]]:
    data = yaml.safe_load((HERE / "field_map.yaml").read_text(encoding="utf-8"))
    return {k: [str(x) for x in v] for k, v in data.items()}


@lru_cache
def mitre_hints() -> list[tuple[re.Pattern[str], str, str]]:
    data = yaml.safe_load((HERE / "mitre_hints.yaml").read_text(encoding="utf-8"))
    return [(re.compile(h["pattern"], re.I), h["technique"], h["reason"]) for h in data]


@dataclass
class MitreHint:
    technique: str
    reason: str
    explicit: bool = False   # True: техника указана в самом алерте


@dataclass
class TimelineEntry:
    time: str
    summary: str


@dataclass
class AlertSummary:
    name: str = ""
    severity: str = ""
    description: str = ""
    source_format: str = "generic"
    times: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    src_ips: list[str] = field(default_factory=list)
    dest_ips: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    parent_processes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    mitre: list[MitreHint] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    raw: Any = None

    @property
    def first_seen(self) -> str:
        return min(self.times, key=_sort_key) if self.times else ""

    @property
    def last_seen(self) -> str:
        return max(self.times, key=_sort_key) if self.times else ""

    @property
    def all_ips(self) -> list[str]:
        return list(dict.fromkeys(self.src_ips + self.dest_ips))

    def query_params(self) -> dict[str, str]:
        """Параметры для генератора запросов, взятые из алерта."""
        ext_ip = next((i.value for i in self.iocs if i.type.value == "ipv4" and i.scope == "public"), "")
        return {
            "user": _short_user(self.users[0]) if self.users else "",
            "host": self.hosts[0] if self.hosts else "",
            "ip": ext_ip or (self.all_ips[0] if self.all_ips else ""),
            "domain": self.domains[0] if self.domains else next(
                (i.value for i in self.iocs if i.type.value == "domain" and i.scope == ""), ""),
            "hash": next((i.value for i in self.iocs if i.type.value in ("sha256", "sha1", "md5")), ""),
            "process": _basename(self.processes[0]) if self.processes else "",
        }


def _short_user(u: str) -> str:
    return u.split("\\")[-1].split("@")[0]


def _basename(p: str) -> str:
    return re.split(r"[\\/]", p)[-1]


def _sort_key(t: str) -> str:
    try:
        return datetime.fromisoformat(t.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return t


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            out.extend(_flatten(v, f"{prefix}[{idx}]."))
    else:
        out.append((prefix[:-1], obj))
    return out


def _key_of(path: str) -> tuple[str, str]:
    """('a.[0].src_ip') -> ('src_ip', 'a.src_ip'): последний ключ и путь без индексов."""
    parts = [p for p in path.split(".") if not (p.startswith("[") and p.endswith("]"))]
    return (parts[-1] if parts else path), ".".join(parts)


def _collect(flat: list[tuple[str, Any]], category: str) -> list[str]:
    wanted = {k.lower() for k in field_map()[category]}
    values: list[str] = []
    for path, v in flat:
        leaf, clean = _key_of(path)
        if v in (None, "", "-", "N/A") or isinstance(v, bool):
            continue
        # совпадение по последнему ключу или по полному пути (ECS: source.ip)
        if leaf.lower() in wanted or clean.lower() in wanted or any(clean.lower().endswith("." + w) for w in wanted
                                                                     if "." in w):
            sv = str(v).strip()
            if sv and sv not in values:
                values.append(sv)
    return values


SEVERITY_WORDS = {
    "informational": "informational", "info": "informational", "low": "low", "medium": "medium",
    "moderate": "medium", "high": "high", "critical": "critical", "urgent": "critical",
    "низкий": "low", "средний": "medium", "высокий": "high", "критический": "critical",
}


def normalize_severity(raw: str) -> str:
    s = raw.strip().lower()
    if s in SEVERITY_WORDS:
        return SEVERITY_WORDS[s]
    try:
        n = float(s)
    except ValueError:
        return raw
    # Шкалы 0-10 (KUMA priority, ECS) и 0-100 (risk score)
    if n > 10:
        n /= 10
    return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low"


def detect_format(flat_keys: set[str]) -> str:
    keys = {k.lower() for k in flat_keys}
    if {"correlationrulename", "deviceeventclassid"} & keys or any(k.startswith("devicecustom") for k in keys):
        return "kuma"
    if {"search_name", "_time", "orig_sid", "urgency"} & keys or "sourcetype" in keys:
        return "splunk"
    if "@timestamp" in keys or any(k.startswith(("event.", "kibana.")) for k in keys):
        return "elastic"
    if {"alertid", "devicename", "initiatingprocessfilename"} & keys:
        return "defender"
    return "generic"


def _timeline(data: Any) -> list[TimelineEntry]:
    """Таймлайн из вложенных событий (списков объектов, где у каждого есть время)."""
    time_keys = {k.lower() for k in field_map()["time"]}
    entries: list[TimelineEntry] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    tk = next((k for k in item if k.lower() in time_keys), None)
                    if tk:
                        flat = _flatten(item)
                        bits = []
                        for cat in ("event_id", "name", "user", "host", "src_ip", "dest_ip", "process", "command"):
                            vals = _collect(flat, cat)
                            if vals:
                                bits.append(f"{cat}={vals[0][:120]}")
                        entries.append(TimelineEntry(str(item[tk]), ", ".join(bits)))
                walk(item)
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)

    walk(data)
    return sorted(entries, key=lambda e: _sort_key(e.time))


def _mitre(flat: list[tuple[str, Any]], blob: str) -> list[MitreHint]:
    hints: dict[str, MitreHint] = {}
    for v in _collect(flat, "mitre") + re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", blob):
        for t in re.findall(r"T1\d{3}(?:\.\d{3})?", v):
            hints.setdefault(t, MitreHint(t, "указано в алерте", True))
    for rx, tech, reason in mitre_hints():
        if rx.search(blob) and tech not in hints:
            hints[tech] = MitreHint(tech, reason)
    return list(hints.values())


def parse_alert(raw: str | dict[str, Any] | list[Any], allowlist: Allowlist | None = None) -> AlertSummary:
    """Разобрать алерт. Принимает JSON-строку, dict или list (несколько событий)."""
    data = json.loads(raw) if isinstance(raw, str) else raw
    flat = _flatten(data)
    blob = json.dumps(data, ensure_ascii=False)

    hosts: list[str] = []
    src_ips: list[str] = []
    dest_ips: list[str] = []
    for v in _collect(flat, "host"):
        (dest_ips if _is_ip(v) else hosts).append(v)
    for v in _collect(flat, "src_ip"):
        (src_ips if _is_ip(v) else hosts).append(v)
    for v in _collect(flat, "dest_ip") + _collect(flat, "ip"):
        (dest_ips if _is_ip(v) else hosts).append(v)
    src_set = set(src_ips)
    dest_ips = [ip for ip in dest_ips if ip not in src_set]

    names = _collect(flat, "name")
    sev = _collect(flat, "severity")
    desc = _collect(flat, "description")
    return AlertSummary(
        name=names[0] if names else "",
        severity=normalize_severity(sev[0]) if sev else "",
        description=desc[0] if desc else "",
        source_format=detect_format({_key_of(p)[1] for p, _ in flat}),
        times=sorted(_collect(flat, "time"), key=_sort_key),
        hosts=list(dict.fromkeys(hosts)),
        users=_collect(flat, "user"),
        src_ips=list(dict.fromkeys(src_ips)),
        dest_ips=list(dict.fromkeys(dest_ips)),
        processes=_collect(flat, "process"),
        parent_processes=_collect(flat, "parent_process"),
        commands=_collect(flat, "command"),
        files=_collect(flat, "file"),
        hashes=_collect(flat, "hash"),
        urls=_collect(flat, "url"),
        domains=_collect(flat, "domain"),
        event_ids=_collect(flat, "event_id"),
        mitre=_mitre(flat, blob),
        timeline=_timeline(data),
        iocs=extract(blob.replace("\\\\", "\\"), allowlist=allowlist),
        raw=data,
    )
