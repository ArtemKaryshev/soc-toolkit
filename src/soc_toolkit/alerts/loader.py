"""Загрузка алерта из того, что реально выгружают SIEM.

Принимается:
- обычный JSON, массив алертов, NDJSON (по объекту на строку), несколько объектов подряд;
- JSON с висячими запятыми, комментариями // и в виде Python-словаря (одинарные кавычки, True/None);
- текст, обёрнутый в ```json ... ```;
- «сырое» событие без JSON: CEF, key=value (Splunk _raw, KUMA Raw), Windows XML, многострочный
  формат «Поле: значение» из журнала безопасности Windows.

Внутри JSON строковые поля с вложенным JSON (Splunk _raw, Sentinel ExtendedProperties, KUMA Raw)
раскрываются, а поля с key=value / CEF / XML дополняются разобранной копией <поле>_parsed.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

RAW_KEYS = {"_raw", "raw", "rawevent", "raw_event", "message", "payload", "event_original", "original",
            "extendedproperties", "additionaldata", "data", "log", "full_log", "event.original", "details"}

CEF_HEADER = ("cef_version", "device_vendor", "device_product", "device_version", "signature_id", "name",
              "severity")
_KV = re.compile(
    r"""([A-Za-z_][\w.\-]*)=(?!=)"""                                 # ключ= (но не base64-хвост "==")
    r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:[^\\]|\\.)*?)"""      # "значение", 'значение' или до след. ключа
    r"""(?=\s+[A-Za-z_][\w.\-]*=(?!=)|\s*$)""", re.S)
_XML_DATA = re.compile(r"""<Data\s+Name=["']([^"']+)["']\s*>(.*?)</Data>""", re.S | re.I)
_XML_TAG = re.compile(r"<(EventID|Computer|Channel|Provider\s+Name=['\"]([^'\"]+)['\"])[^>]*?>([^<]*)<", re.I)
_XML_TIME = re.compile(r"""<TimeCreated\s+SystemTime=["']([^"']+)["']""", re.I)
_COLON_LINE = re.compile(r"^\s*([A-Za-zА-Яа-яЁё][\w .\-/()]{1,60}?):\s+(\S.*)$")


class AlertFormatError(json.JSONDecodeError):
    """Текст не удалось распознать ни как JSON, ни как сырое событие."""


def load_alert_data(text: str) -> Any:
    """Строка из SIEM -> dict/list. Бросает AlertFormatError, если ничего не подошло."""
    s = text.strip().lstrip("﻿")
    s = re.sub(r"^```[\w-]*\s*|\s*```$", "", s)
    data = _try_json(s)
    if data is None:
        parsed = parse_raw_event(s)
        if not parsed:
            raise AlertFormatError("Не удалось распознать алерт: это не JSON, не CEF, не key=value и не XML", s, 0)
        data = parsed
    return expand(data)


def _try_json(s: str) -> Any:
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    # NDJSON и несколько объектов подряд
    dec = json.JSONDecoder()
    items: list[Any] = []
    pos = 0
    while pos < len(s):
        while pos < len(s) and s[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(s):
            break
        try:
            obj, pos = dec.raw_decode(s, pos)
        except json.JSONDecodeError:
            items = []
            break
        items.append(obj)
    if items:
        return items[0] if len(items) == 1 else items
    # Висячие запятые и комментарии
    cleaned = re.sub(r"(?m)^\s*//.*$", "", s)
    cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Python-словарь (так печатают print(dict) и некоторые скрипты выгрузки)
    if s[:1] in "{[":
        try:
            value = ast.literal_eval(s)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return None
        if isinstance(value, (dict, list)):
            return value
    return None


def parse_raw_event(s: str) -> dict[str, Any]:
    """Сырое событие (CEF, key=value, Windows XML, «Поле: значение») -> dict. Пустой dict, если не похоже."""
    s = s.strip()
    if "CEF:" in s:
        return _parse_cef(s[s.index("CEF:"):])
    if "<Event" in s and "</Event>" in s:
        return _parse_xml(s)
    kv = _parse_kv(s)
    if len(kv) >= 3:
        return kv
    colon = _parse_colon_lines(s)
    if len(colon) >= 3:
        return colon
    return {}


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v.replace('\\"', '"').replace("\\=", "=").replace("\\\\", "\\")


def _parse_kv(s: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # Многострочный формат Splunk WinEventLog: Поле=значение на каждой строке
    lines = [ln for ln in s.splitlines() if ln.strip()]
    if len(lines) >= 3 and sum(bool(re.match(r"^\s*[A-Za-z_][\w .\-]*=", ln)) for ln in lines) >= len(lines) / 2:
        for ln in lines:
            m = re.match(r"^\s*([A-Za-z_][\w .\-]*?)=(.*)$", ln)
            if m:
                out.setdefault(m.group(1).strip().replace(" ", "_"), _unquote(m.group(2)))
        if len(out) >= 3:
            return out
        out = {}
    for m in _KV.finditer(s):
        out.setdefault(m.group(1), _unquote(m.group(2)))
    return out


def _parse_cef(s: str) -> dict[str, Any]:
    parts = re.split(r"(?<!\\)\|", s, maxsplit=7)
    out: dict[str, Any] = {}
    for key, value in zip(CEF_HEADER, parts, strict=False):
        out[key] = value.replace("\\|", "|").removeprefix("CEF:")
    if len(parts) == 8:
        out.update(_parse_kv(parts[7]))
    return out


def _parse_xml(s: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for m in _XML_TAG.finditer(s):
        tag = m.group(1)
        if tag.lower().startswith("provider"):
            out["Provider"] = m.group(2)
        elif m.group(3).strip():
            out[tag] = m.group(3).strip()
    t = _XML_TIME.search(s)
    if t:
        out["TimeCreated"] = t.group(1)
    for name, value in _XML_DATA.findall(s):
        out[name] = value.strip()
    return out


def _parse_colon_lines(s: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ln in s.splitlines():
        m = _COLON_LINE.match(ln)
        if m:
            key = re.sub(r"[^\w]+", "_", m.group(1).strip()).strip("_")
            out.setdefault(key, m.group(2).strip())
    return out


def expand(obj: Any, depth: int = 0) -> Any:
    """Раскрыть вложенный JSON в строках и добавить разбор сырых событий."""
    if depth > 6:
        return obj
    if isinstance(obj, list):
        return [expand(v, depth + 1) for v in obj]
    if not isinstance(obj, dict):
        return obj
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if isinstance(v, str):
            sv = v.strip()
            if sv[:1] in "{[" and sv[-1:] in "}]":
                try:
                    out[k] = expand(json.loads(sv), depth + 1)
                    continue
                except json.JSONDecodeError:
                    pass
            if str(k).lower() in RAW_KEYS and len(sv) > 20:
                parsed = parse_raw_event(sv)
                if parsed:
                    out[k] = v
                    out[f"{k}_parsed"] = parsed
                    continue
            out[k] = v
        else:
            out[k] = expand(v, depth + 1)
    return out
