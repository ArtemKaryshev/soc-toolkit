"""Офлайн-справочник: Windows EventID, MITRE ATT&CK, LOLBAS.

Данные загружаются лениво. Если в домашней папке приложения есть обновлённые файлы
(после `soc-toolkit update-data`), используются они, иначе встроенные.
"""

from __future__ import annotations

import gzip
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..config import app_home

BUILTIN = Path(__file__).resolve().parent / "data"


def _data_file(name: str) -> Path:
    user = app_home() / "data" / name
    return user if user.is_file() else BUILTIN / name


def _read_gz(name: str) -> Any:
    with gzip.open(_data_file(name), "rt", encoding="utf-8") as f:
        return json.load(f)


@lru_cache
def eventids() -> dict[str, list[dict[str, Any]]]:
    return yaml.safe_load((BUILTIN / "eventids.yaml").read_text(encoding="utf-8"))


@lru_cache
def mitre() -> dict[str, Any]:
    return _read_gz("mitre.json.gz")


@lru_cache
def lolbas() -> list[dict[str, Any]]:
    return _read_gz("lolbas.json.gz")


@lru_cache
def _technique_index() -> dict[str, dict[str, Any]]:
    return {t["id"].upper(): t for t in mitre()["techniques"]}


def technique(technique_id: str) -> dict[str, Any] | None:
    return _technique_index().get(technique_id.strip().upper())


def technique_name(technique_id: str) -> str:
    t = technique(technique_id)
    return t["full_name"] if t else ""


def _matches(record: Any, terms: list[str]) -> bool:
    blob = json.dumps(record, ensure_ascii=False).lower()
    return all(t in blob for t in terms)


def _terms(query: str) -> list[str]:
    return [t for t in re.split(r"\s+", query.strip().lower()) if t]


def search_events(query: str = "", log: str = "") -> list[dict[str, Any]]:
    rows = eventids()["events"]
    if log:
        rows = [r for r in rows if log.lower() in str(r["log"]).lower()]
    terms = _terms(query)
    if len(terms) == 1 and terms[0].isdigit():  # точный поиск по номеру события
        return [r for r in rows if str(r["id"]) == terms[0]]
    return [r for r in rows if _matches(r, terms)] if terms else rows


def search_techniques(query: str = "", tactic: str = "", include_sub: bool = True) -> list[dict[str, Any]]:
    rows = mitre()["techniques"]
    if tactic:
        rows = [t for t in rows if tactic in t["tactics"]]
    if not include_sub:
        rows = [t for t in rows if not t["is_subtechnique"]]
    terms = _terms(query)
    if len(terms) == 1 and re.fullmatch(r"t\d{4}(\.\d{3})?", terms[0]):
        return [t for t in rows if t["id"].lower() == terms[0] or t["id"].lower().startswith(terms[0] + ".")]
    if not terms:
        return rows
    # сначала совпадения в названии, потом в описании
    by_name = [t for t in rows if all(x in t["full_name"].lower() for x in terms)]
    # точнее совпадение (название начинается с запроса, короче) — выше
    by_name.sort(key=lambda t: (not t["full_name"].lower().startswith(terms[0]), t["is_subtechnique"],
                                len(t["full_name"])))
    rest = [t for t in rows if t not in by_name and _matches(t, terms)]
    return by_name + rest


def search_groups(query: str = "") -> list[dict[str, Any]]:
    terms = _terms(query)
    return [g for g in mitre()["groups"] if _matches(g, terms)] if terms else mitre()["groups"]


def search_lolbas(query: str = "", category: str = "") -> list[dict[str, Any]]:
    rows = lolbas()
    if category:
        rows = [r for r in rows if category in r["categories"]]
    terms = _terms(query)
    if not terms:
        return rows
    by_name = [r for r in rows if all(x in r["name"].lower() for x in terms)]
    by_name.sort(key=lambda r: (not r["name"].lower().startswith(terms[0]), len(r["name"])))
    rest = [r for r in rows if r not in by_name and _matches(r, terms)]
    return by_name + rest


def lolbas_categories() -> list[str]:
    return sorted({c for r in lolbas() for c in r["categories"]})


def tactics() -> list[dict[str, Any]]:
    return mitre()["tactics"]


def search_all(query: str) -> dict[str, list[dict[str, Any]]]:
    return {
        "events": search_events(query),
        "techniques": search_techniques(query),
        "lolbas": search_lolbas(query),
        "groups": search_groups(query),
    }
