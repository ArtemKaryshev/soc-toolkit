"""Генератор запросов Splunk SPL и Kaspersky KUMA SQL по шаблонам из YAML.

Встроенные шаблоны лежат в queries/templates/*.yaml. Свои шаблоны можно положить в папку,
указанную в config.toml (queries.custom_templates_dir): шаблон с тем же id заменит встроенный.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import SandboxedEnvironment

from ..config import QuerySettings

log = logging.getLogger(__name__)
BUILTIN_DIR = Path(__file__).resolve().parent / "templates"


@dataclass
class Param:
    name: str
    label: str
    default: str = ""
    type: str = "str"


@dataclass
class QueryTemplate:
    id: str
    title: str
    category: str
    description: str
    spl: str
    kuma: str
    params: list[Param] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    source: str = "builtin"


@dataclass
class RenderedQuery:
    template: QueryTemplate
    spl: str
    kuma: str
    params: dict[str, str]


# --------------------------------------------------------------------------- экранирование

def esc_spl(value: Any) -> str:
    """Экранирование для строки SPL в двойных кавычках."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def esc_sql(value: Any) -> str:
    """Экранирование для строки SQL в одинарных кавычках (ClickHouse/KUMA)."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def like(value: Any) -> str:
    """Splunk-маска -> шаблон SQL LIKE: * -> %, а _ и % экранируются."""
    s = esc_sql(value).replace("%", "\\%").replace("_", "\\_").replace("*", "%")
    return s or "%"


def _env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False, keep_trailing_newline=False)
    env.filters.update(q=esc_spl, sq=esc_sql, like=like)
    return env


ENV = _env()


# --------------------------------------------------------------------------- загрузка

def _parse(item: dict[str, Any], source: str) -> QueryTemplate:
    params = [Param(name, str(p.get("label", name)), str(p.get("default", "")), str(p.get("type", "str")))
              for name, p in (item.get("params") or {}).items()]
    t = QueryTemplate(
        id=str(item["id"]), title=str(item["title"]), category=str(item.get("category", "Прочее")),
        description=str(item.get("description", "")), spl=str(item["spl"]).strip(),
        kuma=str(item["kuma"]).strip(), params=params, mitre=[str(m) for m in item.get("mitre") or []],
        source=source,
    )
    # проверяем синтаксис сразу при загрузке, чтобы ошибка была понятной
    ENV.from_string(t.spl)
    ENV.from_string(t.kuma)
    return t


def load_templates(custom_dir: str | Path | None = None) -> list[QueryTemplate]:
    templates: dict[str, QueryTemplate] = {}
    dirs = [(BUILTIN_DIR, "builtin")]
    if custom_dir:
        dirs.append((Path(custom_dir).expanduser(), "custom"))
    for d, source in dirs:
        if not d.is_dir():
            log.warning("Папка шаблонов не найдена: %s", d)
            continue
        for f in sorted(d.glob("*.y*ml")):
            for item in yaml.safe_load(f.read_text(encoding="utf-8")) or []:
                try:
                    templates[item["id"]] = _parse(item, source if source == "builtin" else f.name)
                except (KeyError, TemplateError) as e:
                    log.error("Ошибка в шаблоне %s из %s: %s", item.get("id", "?"), f, e)
    return list(templates.values())


class QueryEngine:
    def __init__(self, settings: QuerySettings | None = None):
        self.settings = settings or QuerySettings()
        self.templates = load_templates(self.settings.custom_templates_dir)
        self.by_id = {t.id: t for t in self.templates}

    def categories(self) -> list[str]:
        return list(dict.fromkeys(t.category for t in self.templates))

    def env_values(self, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        s = self.settings
        values: dict[str, Any] = {
            "win_index": s.win_index, "sysmon_index": s.sysmon_index, "sysmon_sourcetype": s.sysmon_sourcetype,
            "proxy_index": s.proxy_index, "dns_index": s.dns_index, "email_index": s.email_index,
            "firewall_index": s.firewall_index, "earliest": s.earliest, "kuma_limit": int(s.kuma_limit),
        }
        values.update({k: v for k, v in (overrides or {}).items() if v not in (None, "")})
        return values

    def render(self, template_id: str, params: dict[str, Any] | None = None,
               env: dict[str, Any] | None = None) -> RenderedQuery:
        t = self.by_id[template_id]
        params = params or {}
        values = self.env_values(env)
        used: dict[str, str] = {}
        for p in t.params:
            raw = str(params.get(p.name) or "").strip() or p.default
            if p.type == "int":
                raw = raw if raw.isdigit() else p.default
            values[p.name] = int(raw) if p.type == "int" else raw
            used[p.name] = raw
        return RenderedQuery(t, ENV.from_string(t.spl).render(values), ENV.from_string(t.kuma).render(values), used)

    def suggest(self, alert_params: dict[str, str]) -> list[str]:
        """Шаблоны, для которых в алерте есть все ключевые параметры (без порогов)."""
        have = {k for k, v in alert_params.items() if v}
        out = []
        for t in self.templates:
            needed = {p.name for p in t.params if p.type != "int" and p.name in
                      {"user", "host", "ip", "domain", "hash", "process"}}
            if needed and needed <= have:
                out.append(t.id)
        return out
