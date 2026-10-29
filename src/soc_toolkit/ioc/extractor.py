"""Извлечение индикаторов компрометации из текста.

Основная функция: extract(). Она:
- возвращает обезвреженным индикаторам рабочий вид (refang);
- раскодирует base64 и PowerShell -EncodedCommand и ищет IOC внутри;
- классифицирует IP (public/private/...) и домены (internal);
- помечает индикаторы из allowlist;
- считает количество вхождений и сохраняет контекст первого вхождения.
"""

from __future__ import annotations

import base64
import binascii
import csv
import io
import ipaddress
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

from . import patterns as P

log = logging.getLogger(__name__)


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    CVE = "cve"
    MITRE = "mitre"
    FILENAME = "filename"
    WIN_PATH = "path"
    REG_KEY = "registry"


NETWORK_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL})
HASH_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512})
# Типы, которые имеет смысл проверять во внешних сервисах репутации
CHECKABLE_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL} | HASH_TYPES)


@dataclass
class IOC:
    type: IOCType
    value: str
    scope: str = ""                       # public / private / loopback / internal ...
    tags: set[str] = field(default_factory=set)
    count: int = 1
    context: str = ""                     # фрагмент текста вокруг первого вхождения

    @property
    def defanged(self) -> str:
        return defang(self.value) if self.type in NETWORK_TYPES else self.value

    @property
    def is_external(self) -> bool:
        """Индикатор относится к внешнему миру и не в allowlist: кандидат на проверку репутации."""
        if self.type not in CHECKABLE_TYPES or "allowlisted" in self.tags:
            return False
        return self.scope in ("", "public")

    def as_row(self, defanged: bool = False) -> dict[str, str | int]:
        return {
            "type": self.type.value,
            "value": self.defanged if defanged else self.value,
            "scope": self.scope,
            "tags": ", ".join(sorted(self.tags)),
            "count": self.count,
            "context": self.context,
        }


# --------------------------------------------------------------------------- defang

def refang(text: str) -> str:
    """hxxp -> http, [.] -> ., [@] -> @ и т.д."""
    for pattern, repl in P.DEFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Обезвредить индикатор для безопасной вставки в отчёт, тикет или чат."""
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", value, re.I)
    if m:
        scheme = m.group(1).lower().replace("http", "hxxp").replace("ftp", "fxp")
        rest = value[m.end():]
        host, sep, path = rest.partition("/")
        return f"{scheme}[://]{host.replace('.', '[.]')}{sep}{path}"
    if "@" in value:
        user, _, host = value.rpartition("@")
        return f"{user}[@]{host.replace('.', '[.]')}"
    if ":" in value and "." not in value:  # IPv6
        return value.replace(":", "[:]")
    return value.replace(".", "[.]")


# --------------------------------------------------------------------------- классификация

def classify_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified or ip.is_reserved:
        return "reserved"
    if ip.is_private:  # включает RFC1918, CGNAT 100.64/10, документационные сети
        return "private"
    return "public"


def domain_scope(domain: str) -> str:
    return "internal" if domain.rsplit(".", 1)[-1].lower() in P.INTERNAL_TLDS else ""


def host_scope(host: str) -> str:
    """Область для хоста из URL: IP классифицируем как IP, имя как домен."""
    return classify_ip(host) if P.IPV4.fullmatch(host) or ":" in host else domain_scope(host)


def _looks_like_domain(candidate: str) -> bool:
    tld = candidate.rsplit(".", 1)[-1].lower()
    if tld in P.FILE_EXTENSIONS or not tld.isalpha():
        return False
    return tld in P.COMMON_TLDS or len(tld) == 2 or tld == "рф"


# --------------------------------------------------------------------------- allowlist

@dataclass
class Allowlist:
    domains: set[str] = field(default_factory=set)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    hashes: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, paths: Iterable[Path]) -> Allowlist:
        al = cls()
        for p in paths:
            if not p.is_file():
                log.warning("Allowlist не найден: %s", p)
                continue
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            al.domains.update(d.lower().strip(".") for d in data.get("domains") or [])
            al.hashes.update(h.lower() for h in data.get("hashes") or [])
            for net in data.get("ips") or []:
                try:
                    al.networks.append(ipaddress.ip_network(str(net), strict=False))
                except ValueError:
                    log.warning("Некорректная запись allowlist: %s", net)
        return al

    @classmethod
    def builtin(cls) -> Allowlist:
        return cls.load([Path(__file__).with_name("allowlist.yaml")])

    def matches(self, ioc: IOC) -> bool:
        if ioc.type in (IOCType.IPV4, IOCType.IPV6):
            try:
                ip = ipaddress.ip_address(ioc.value.split("%")[0])
            except ValueError:
                return False
            return any(ip in n for n in self.networks if n.version == ip.version)
        if ioc.type in HASH_TYPES:
            return ioc.value.lower() in self.hashes
        host = ""
        if ioc.type == IOCType.DOMAIN:
            host = ioc.value
        elif ioc.type == IOCType.URL:
            host = urlsplit(ioc.value).hostname or ""
        elif ioc.type == IOCType.EMAIL:
            host = ioc.value.rsplit("@", 1)[-1]
        host = host.lower()
        return bool(host) and any(host == d or host.endswith("." + d) for d in self.domains)


# --------------------------------------------------------------------------- декодеры

def _printable_ratio(s: str) -> float:
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in s) / max(len(s), 1)


def decode_base64(blob: str) -> str | None:
    """Попробовать раскодировать base64 как UTF-16LE (PowerShell) или UTF-8. None, если это не текст."""
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if len(text) >= 4 and _printable_ratio(text) > 0.95:
            return text
    return None


@dataclass
class DecodedBlob:
    kind: str       # powershell / base64 / urlencoded
    source: str     # исходный фрагмент (обрезанный)
    decoded: str


def find_encoded(text: str, max_depth: int = 3) -> list[DecodedBlob]:
    """Найти и раскодировать закодированные фрагменты (рекурсивно, до max_depth уровней)."""
    found: list[DecodedBlob] = []
    seen: set[str] = set()

    def walk(chunk: str, depth: int) -> None:
        if depth > max_depth:
            return
        for m in P.PS_ENCODED.finditer(chunk):
            blob = m.group(1)
            if blob in seen:
                continue
            seen.add(blob)
            dec = decode_base64(blob)
            if dec:
                found.append(DecodedBlob("powershell", blob[:80], dec))
                walk(dec, depth + 1)
        for m in P.BASE64.finditer(chunk):
            blob = m.group(0)
            # длинные hex-строки (хэши) тоже подходят под алфавит base64: пропускаем
            if blob in seen or re.fullmatch(r"[0-9A-Fa-f]+", blob):
                continue
            seen.add(blob)
            dec = decode_base64(blob)
            if dec:
                found.append(DecodedBlob("base64", blob[:80], dec))
                walk(dec, depth + 1)
        if re.search(r"%[0-9A-Fa-f]{2}", chunk):
            dec = unquote(chunk)
            if dec != chunk and dec not in seen:
                seen.add(dec)
                found.append(DecodedBlob("urlencoded", chunk[:80], dec))

    walk(text, 0)
    return found


# --------------------------------------------------------------------------- извлечение

def _context(text: str, start: int, end: int, width: int = 40) -> str:
    s = text[max(0, start - width): end + width].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", s).strip()


class _Collector:
    def __init__(self) -> None:
        self.items: dict[tuple[IOCType, str], IOC] = {}

    def add(self, kind: IOCType, value: str, text: str, span: tuple[int, int],
            scope: str = "", tags: Iterable[str] = ()) -> None:
        key = (kind, value.lower())
        if key in self.items:
            self.items[key].count += 1
            self.items[key].tags.update(tags)
            return
        self.items[key] = IOC(kind, value, scope, set(tags), 1, _context(text, *span))


def _scan(text: str, col: _Collector, tags: tuple[str, ...] = ()) -> None:
    clean = refang(text)

    url_hosts: set[str] = set()
    for m in P.URL.finditer(clean):
        url = m.group(0).rstrip(".,;:!?")
        col.add(IOCType.URL, url, clean, m.span(), host_scope(urlsplit(url).hostname or ""), tags)
        url_hosts.add((urlsplit(url).hostname or "").lower())

    email_hosts: set[str] = set()
    for m in P.EMAIL.finditer(clean):
        col.add(IOCType.EMAIL, m.group(0), clean, m.span(), domain_scope(m.group(0)), tags)
        email_hosts.add(m.group(0).rsplit("@", 1)[1].lower())

    for kind, rx in ((IOCType.SHA512, P.SHA512), (IOCType.SHA256, P.SHA256),
                     (IOCType.SHA1, P.SHA1), (IOCType.MD5, P.MD5)):
        for m in rx.finditer(clean):
            col.add(kind, m.group(0).lower(), clean, m.span(), tags=tags)

    for m in P.CVE.finditer(clean):
        col.add(IOCType.CVE, m.group(0).upper(), clean, m.span(), tags=tags)
    for m in P.MITRE.finditer(clean):
        col.add(IOCType.MITRE, m.group(0), clean, m.span(), tags=tags)

    for m in P.IPV4.finditer(clean):
        col.add(IOCType.IPV4, m.group(0), clean, m.span(), classify_ip(m.group(0)), tags)
    for m in P.IPV6.finditer(clean):
        value = m.group(0)
        scope = classify_ip(value)
        if scope in ("invalid", "reserved") or value.count(":") < 2:
            continue
        col.add(IOCType.IPV6, value.lower(), clean, m.span(), scope, tags)

    for m in P.DOMAIN.finditer(clean):
        d = m.group(0).lower()
        if P.IPV4.fullmatch(d) or not _looks_like_domain(d):
            continue
        # домен из e-mail не дублируем отдельно, а домен из URL оставляем: его удобно проверять
        if d in email_hosts and d not in url_hosts:
            continue
        col.add(IOCType.DOMAIN, d, clean, m.span(), domain_scope(d), tags)

    for m in P.REG_KEY.finditer(clean):
        col.add(IOCType.REG_KEY, m.group(0).rstrip("\\ ."), clean, m.span(), tags=tags)
    for m in P.WIN_PATH.finditer(clean):
        value = m.group(0).rstrip(". ")
        if len(value) > 3:
            col.add(IOCType.WIN_PATH, value, clean, m.span(), tags=tags)
    for m in P.FILENAME.finditer(clean):
        col.add(IOCType.FILENAME, m.group(0).strip(), clean, m.span(), tags=tags)


def extract(text: str, *, decode: bool = True, allowlist: Allowlist | None = None,
            include_internal: bool = True, types: Iterable[str] | None = None) -> list[IOC]:
    """Найти все IOC в тексте.

    decode            раскодировать base64/PowerShell/URL-encoding и искать IOC внутри (тег "decoded")
    allowlist         пометить совпадения тегом "allowlisted"
    include_internal  оставлять ли внутренние/служебные адреса и домены
    types             ограничить типы, например {"ipv4", "domain"}
    """
    col = _Collector()
    _scan(text, col)
    if decode:
        for blob in find_encoded(text):
            _scan(blob.decoded, col, ("decoded", blob.kind))

    result = list(col.items.values())
    if allowlist:
        for i in result:
            if allowlist.matches(i):
                i.tags.add("allowlisted")
    if not include_internal:
        result = [i for i in result if i.scope in ("", "public")]
    if types:
        wanted = {str(t) for t in types}
        result = [i for i in result if i.type.value in wanted]
    return result


# --------------------------------------------------------------------------- экспорт

def to_csv(iocs: Iterable[IOC], defanged: bool = False) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["type", "value", "scope", "tags", "count", "context"])
    writer.writeheader()
    for i in iocs:
        writer.writerow(i.as_row(defanged))
    return buf.getvalue()


def to_json(iocs: Iterable[IOC], defanged: bool = False) -> str:
    return json.dumps([i.as_row(defanged) for i in iocs], ensure_ascii=False, indent=2)


def to_stix(iocs: Iterable[IOC]) -> str:
    """Простой STIX 2.1 bundle с индикаторами (для обмена с TIP/MISP/OpenCTI)."""
    import uuid
    from datetime import UTC, datetime

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    patterns = {
        IOCType.IPV4: "[ipv4-addr:value = '{}']", IOCType.IPV6: "[ipv6-addr:value = '{}']",
        IOCType.DOMAIN: "[domain-name:value = '{}']", IOCType.URL: "[url:value = '{}']",
        IOCType.EMAIL: "[email-addr:value = '{}']", IOCType.MD5: "[file:hashes.MD5 = '{}']",
        IOCType.SHA1: "[file:hashes.'SHA-1' = '{}']", IOCType.SHA256: "[file:hashes.'SHA-256' = '{}']",
        IOCType.SHA512: "[file:hashes.'SHA-512' = '{}']",
    }
    objects = []
    for i in iocs:
        if i.type not in patterns or "allowlisted" in i.tags:
            continue
        value = i.value.replace("\\", "\\\\").replace("'", "\\'")
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
            "created": now, "modified": now, "valid_from": now, "name": i.value,
            "pattern": patterns[i.type].format(value), "pattern_type": "stix",
            "labels": sorted(i.tags) or ["soc-toolkit"],
        })
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects},
                      ensure_ascii=False, indent=2)
