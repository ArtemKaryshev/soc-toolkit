"""Настройки приложения.

Порядок поиска config.toml:
1. путь из переменной окружения SOC_TOOLKIT_CONFIG;
2. ./config.toml в текущей папке;
3. <домашняя папка приложения>/config.toml.

Домашняя папка приложения (кеш, база кейсов, логи) берётся из SOC_TOOLKIT_HOME,
по умолчанию ~/.soc_toolkit. Ключи API можно задать переменными окружения,
они имеют приоритет над файлом.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent

ENV_KEYS = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "urlhaus": "ABUSECH_API_KEY",
}


def app_home() -> Path:
    home = Path(os.getenv("SOC_TOOLKIT_HOME", Path.home() / ".soc_toolkit")).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    return home


def find_config() -> Path | None:
    candidates = [os.getenv("SOC_TOOLKIT_CONFIG"), Path.cwd() / "config.toml", app_home() / "config.toml"]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    return None


@dataclass
class ReputationSettings:
    enabled: bool = True
    cache_ttl_hours: float = 24.0
    allow_internal: bool = False
    policy_acknowledged: bool = False
    max_workers: int = 4
    timeout: float = 15.0
    max_retries: int = 2
    proxy: str = ""
    verify_tls: bool = True
    # Лимиты бесплатных тарифов: запросов в минуту
    rate_limits: dict[str, int] = field(
        default_factory=lambda: {"virustotal": 4, "abuseipdb": 30, "otx": 60, "greynoise": 10,
                                 "urlhaus": 60, "shodan_internetdb": 60}
    )


@dataclass
class QuerySettings:
    win_index: str = "wineventlog"
    sysmon_index: str = "sysmon"
    sysmon_sourcetype: str = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    proxy_index: str = "proxy"
    dns_index: str = "dns"
    email_index: str = "email"
    firewall_index: str = "firewall"
    earliest: str = "-24h"
    kuma_limit: int = 250
    custom_templates_dir: str = ""


@dataclass
class ReportSettings:
    default_language: str = "ru"
    analyst_name: str = ""
    organization: str = ""
    defang_indicators: bool = True
    custom_templates_dir: str = ""


@dataclass
class IOCSettings:
    allowlist_file: str = ""
    use_builtin_allowlist: bool = True


@dataclass
class Settings:
    api_keys: dict[str, str] = field(default_factory=dict)
    reputation: ReputationSettings = field(default_factory=ReputationSettings)
    queries: QuerySettings = field(default_factory=QuerySettings)
    report: ReportSettings = field(default_factory=ReportSettings)
    ioc: IOCSettings = field(default_factory=IOCSettings)
    log_level: str = "INFO"
    source: Path | None = None
    home: Path = field(default_factory=app_home)

    @property
    def cache_path(self) -> Path:
        return self.home / "cache.sqlite"

    @property
    def cases_path(self) -> Path:
        return self.home / "cases.sqlite"

    @property
    def log_path(self) -> Path:
        return self.home / "soc_toolkit.log"


def _fill(cls: type, raw: dict[str, Any]) -> Any:
    """Создать dataclass из словаря, игнорируя неизвестные ключи (с предупреждением)."""
    known = {f.name for f in fields(cls)}
    unknown = set(raw) - known
    if unknown:
        log.warning("Неизвестные параметры в секции %s: %s", cls.__name__, ", ".join(sorted(unknown)))
    obj = cls(**{k: v for k, v in raw.items() if k in known})
    if isinstance(obj, ReputationSettings) and "rate_limits" in raw:
        obj.rate_limits = {**ReputationSettings().rate_limits, **raw["rate_limits"]}
    return obj


def load_settings(path: Path | None = None) -> Settings:
    path = path or find_config()
    raw: dict[str, Any] = {}
    if path and path.is_file():
        with path.open("rb") as f:
            raw = tomllib.load(f)
    s = Settings(
        api_keys={k: str(v) for k, v in raw.get("api_keys", {}).items() if v},
        reputation=_fill(ReputationSettings, raw.get("reputation", {})),
        queries=_fill(QuerySettings, raw.get("queries", {})),
        report=_fill(ReportSettings, raw.get("report", {})),
        ioc=_fill(IOCSettings, raw.get("ioc", {})),
        log_level=raw.get("log_level", "INFO"),
        source=path,
    )
    for name, env in ENV_KEYS.items():
        if os.getenv(env):
            s.api_keys[name] = os.environ[env]
    return s


def setup_logging(settings: Settings) -> None:
    """Логи в файл с ротацией. API-ключи в лог не пишутся нигде в коде."""
    root = logging.getLogger("soc_toolkit")
    if root.handlers:
        return
    root.setLevel(settings.log_level.upper())
    handler = logging.handlers.RotatingFileHandler(settings.log_path, maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
