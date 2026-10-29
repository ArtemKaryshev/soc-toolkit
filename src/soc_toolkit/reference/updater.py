"""Сборка и обновление офлайн-справочников MITRE ATT&CK и LOLBAS.

Готовые сжатые файлы лежат в reference/data и поставляются с приложением.
Команда `soc-toolkit update-data` скачивает свежие версии в домашнюю папку
приложения, и они начинают использоваться вместо встроенных.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import requests
import yaml

log = logging.getLogger(__name__)

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]


def _clean_text(text: str, limit: int) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # markdown-ссылки -> текст
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[ \t]+", " ", text).strip()
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


def convert_mitre(bundle: dict[str, Any]) -> dict[str, Any]:
    """STIX bundle ATT&CK Enterprise -> компактный словарь техник, тактик и групп."""
    objs = bundle["objects"]
    techniques = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        techniques.append({
            "id": ext["external_id"],
            "name": o["name"],
            "tactics": sorted(tactics, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99),
            "platforms": o.get("x_mitre_platforms", []),
            "data_sources": o.get("x_mitre_data_sources", []),
            "description": _clean_text(o.get("description", ""), 900),
            "detection": _clean_text(o.get("x_mitre_detection", ""), 700),
            "url": ext.get("url", ""),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
        })
    # Имена родительских техник у подтехник: "Command and Scripting Interpreter: PowerShell"
    by_id = {t["id"]: t for t in techniques}
    for t in techniques:
        if t["is_subtechnique"]:
            parent = by_id.get(t["id"].split(".")[0])
            if parent:
                t["full_name"] = f"{parent['name']}: {t['name']}"
        t.setdefault("full_name", t["name"])
    techniques.sort(key=lambda t: [int(x) for x in t["id"][1:].split(".")])

    tactics = []
    for o in objs:
        if o.get("type") == "x-mitre-tactic" and not o.get("x_mitre_deprecated"):
            ext = next(r for r in o["external_references"] if r.get("source_name") == "mitre-attack")
            tactics.append({"id": ext["external_id"], "name": o["name"], "shortname": o["x_mitre_shortname"],
                            "url": ext.get("url", "")})
    tactics.sort(key=lambda t: TACTIC_ORDER.index(t["shortname"]) if t["shortname"] in TACTIC_ORDER else 99)

    groups = []
    for o in objs:
        if o.get("type") == "intrusion-set" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if ext:
                groups.append({"id": ext["external_id"], "name": o["name"], "aliases": o.get("aliases", []),
                               "description": _clean_text(o.get("description", ""), 500), "url": ext.get("url", "")})
    groups.sort(key=lambda g: g["id"])

    # Номер релиза ATT&CK в бандле не хранится, поэтому версией считаем дату изменения матрицы
    version = next((o.get("modified", "")[:10] for o in objs if o.get("type") == "x-mitre-matrix"), "")
    return {"version": version, "tactics": tactics, "techniques": techniques, "groups": groups}


def _lolbas_entry(e: dict[str, Any]) -> dict[str, Any]:
    name = e.get("Name", "")
    commands = [{
        "command": c.get("Command", ""),
        "description": c.get("Description", ""),
        "usecase": c.get("Usecase", ""),
        "category": c.get("Category", ""),
        "privileges": c.get("Privileges", ""),
        "mitre": c.get("MitreID", ""),
    } for c in e.get("Commands") or []]
    detection: list[str] = []
    for d in e.get("Detection") or []:
        if isinstance(d, dict):
            detection.extend(f"{k}: {v}" for k, v in d.items())
    paths = [p.get("Path", "") for p in e.get("Full_Path") or [] if isinstance(p, dict)]
    slug = re.sub(r"\.(exe|dll|vbs|ps1|cmd|bat|js|wsf)$", "", name, flags=re.I)
    return {
        "name": name,
        "description": e.get("Description", ""),
        "type": e.get("Type", ""),
        "categories": sorted({c["category"] for c in commands if c["category"]}),
        "mitre": sorted({c["mitre"] for c in commands if c["mitre"]}),
        "commands": commands,
        "paths": paths,
        "detection": detection,
        "url": e.get("url") or f"https://lolbas-project.github.io/lolbas/{e.get('Type', 'Binaries')}/{slug}/",
    }


def convert_lolbas_api(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for e in entries:
        # в API тип не указан, восстанавливаем из URL
        m = re.search(r"/lolbas/(\w+)/", e.get("url", ""))
        e = {**e, "Type": m.group(1) if m else "Binaries"}
        out.append(_lolbas_entry(e))
    return sorted(out, key=lambda x: x["name"].lower())


def convert_lolbas_yml(paths: Iterable[Path]) -> list[dict[str, Any]]:
    """Сборка из клона репозитория LOLBAS-Project/LOLBAS (папка yml)."""
    type_by_dir = {"OSBinaries": "Binaries", "OtherMSBinaries": "OtherMSBinaries", "OSLibraries": "Libraries",
                   "OSScripts": "Scripts"}
    out = []
    for p in paths:
        if p.parent.name not in type_by_dir:
            continue
        e = yaml.safe_load(p.read_text(encoding="utf-8"))
        out.append(_lolbas_entry({**e, "Type": type_by_dir[p.parent.name]}))
    return sorted(out, key=lambda x: x["name"].lower())


def write_gz(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


def update(target_dir: Path, *, proxy: str = "", timeout: float = 120) -> dict[str, int]:
    """Скачать свежие MITRE ATT&CK и LOLBAS в target_dir. Возвращает количество записей."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    result = {}
    r = requests.get(MITRE_URL, timeout=timeout, proxies=proxies)
    r.raise_for_status()
    mitre = convert_mitre(r.json())
    write_gz(target_dir / "mitre.json.gz", mitre)
    result["mitre_techniques"] = len(mitre["techniques"])
    log.info("MITRE ATT&CK обновлён: %s техник", result["mitre_techniques"])

    r = requests.get(LOLBAS_URL, timeout=timeout, proxies=proxies)
    r.raise_for_status()
    lolbas = convert_lolbas_api(r.json())
    write_gz(target_dir / "lolbas.json.gz", lolbas)
    result["lolbas"] = len(lolbas)
    log.info("LOLBAS обновлён: %s записей", result["lolbas"])
    return result
