"""Проверка репутации: политика, кеш, лимиты, ретраи, параллельные запросы, сводный вердикт."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import requests

from .. import __version__
from ..config import Settings
from ..ioc import CHECKABLE_TYPES, IOC, IOCType
from .base import Provider, ProviderError, RepResult, Verdict
from .cache import ReputationCache
from .providers import PROVIDERS
from .ratelimit import RateLimiter

log = logging.getLogger(__name__)

POLICY_WARNING = (
    "Отправка индикаторов во внешние сервисы (VirusTotal, AbuseIPDB, OTX и др.) может нарушать политику "
    "вашей компании. Владелец сервиса видит, что вы проверяете, а загруженные данные иногда доступны "
    "другим пользователям и самим злоумышленникам (они отслеживают проверки своих IOC). "
    "Не отправляйте внутренние имена, адреса и хэши внутренних файлов без разрешения. "
    "Используйте эту функцию только с одобрения руководителя SOC или в учебных целях."
)


@dataclass
class AggregatedResult:
    indicator: str
    ioc_type: str
    verdict: Verdict
    results: list[RepResult] = field(default_factory=list)

    @property
    def summary(self) -> str:
        parts = [f"{r.provider}: {r.score or r.verdict.value}" for r in self.results
                 if r.verdict not in (Verdict.SKIPPED, Verdict.ERROR)]
        return "; ".join(parts)


def aggregate(results: list[RepResult]) -> Verdict:
    """Сводный вердикт: 'malicious' от двух источников или 'malicious' + 'suspicious' → malicious,
    один 'malicious' → suspicious (чтобы один шумный источник не решал за аналитика)."""
    verdicts = [r.verdict for r in results]
    mal = verdicts.count(Verdict.MALICIOUS)
    sus = verdicts.count(Verdict.SUSPICIOUS)
    if mal >= 2 or (mal == 1 and sus >= 1) or (mal == 1 and len([v for v in verdicts if v.weight >= 0]) == 1):
        return Verdict.MALICIOUS
    if mal or sus:
        return Verdict.SUSPICIOUS
    if Verdict.CLEAN in verdicts:
        return Verdict.CLEAN
    if Verdict.UNKNOWN in verdicts:
        return Verdict.UNKNOWN
    return Verdict.ERROR if Verdict.ERROR in verdicts else Verdict.SKIPPED


class ReputationService:
    def __init__(self, settings: Settings, cache: ReputationCache | None = None,
                 session: requests.Session | None = None):
        self.settings = settings
        rs = settings.reputation
        self.cache = cache if cache is not None else ReputationCache(settings.cache_path, rs.cache_ttl_hours)
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = f"soc-toolkit/{__version__}"
        self.session.verify = rs.verify_tls
        if rs.proxy:
            self.session.proxies = {"http": rs.proxy, "https": rs.proxy}
        self.limiters = {name: RateLimiter(rs.rate_limits.get(name, 30)) for name in PROVIDERS}
        self.providers: dict[str, Provider] = {
            name: cls(self.session, settings.api_keys.get(name, ""), rs.timeout) for name, cls in PROVIDERS.items()
        }

    # ------------------------------------------------------------------ информация

    def available(self) -> list[str]:
        """Провайдеры, которыми можно пользоваться (есть ключ или ключ не нужен)."""
        return [n for n, p in self.providers.items() if p.api_key or not p.requires_key]

    def status(self) -> list[dict[str, str | bool]]:
        return [{"name": n, "title": p.title, "key": bool(p.api_key), "requires_key": p.requires_key,
                 "ready": bool(p.api_key) or not p.requires_key, "signup": p.signup_url,
                 "types": ", ".join(sorted(t.value for t in p.supported))} for n, p in self.providers.items()]

    # ------------------------------------------------------------------ проверки

    def _gate(self, ioc: IOC) -> str:
        """Причина, по которой индикатор нельзя отправлять наружу, или пустая строка."""
        rs = self.settings.reputation
        if not rs.enabled:
            return "проверка репутации отключена в настройках"
        if not rs.policy_acknowledged:
            return "не подтверждено предупреждение о политике компании"
        if ioc.type not in CHECKABLE_TYPES:
            return "тип не проверяется"
        if ioc.scope not in ("", "public") and not rs.allow_internal:
            return f"внутренний индикатор ({ioc.scope}) не отправляется"
        return ""

    def _check_one(self, provider: Provider, ioc: IOC) -> RepResult:
        skip = lambda reason: RepResult(provider.name, ioc.value, ioc.type.value, Verdict.SKIPPED,  # noqa: E731
                                        error=reason)
        if not provider.supports(ioc.type):
            return skip("тип не поддерживается")
        if provider.requires_key and not provider.api_key:
            return skip("нет API-ключа")
        cached = self.cache.get(provider.name, ioc.value)
        if cached:
            return cached
        attempts = self.settings.reputation.max_retries + 1
        for attempt in range(1, attempts + 1):
            if not self.limiters[provider.name].acquire():
                return RepResult(provider.name, ioc.value, ioc.type.value, Verdict.ERROR,
                                 error="лимит запросов исчерпан, попробуйте позже")
            try:
                res = provider.check(ioc.type, ioc.value)
                self.cache.put(res)
                return res
            except ProviderError as e:
                log.warning("%s %s: %s (попытка %s/%s)", provider.name, ioc.value, e, attempt, attempts)
                if not e.retryable or attempt == attempts:
                    return RepResult(provider.name, ioc.value, ioc.type.value, Verdict.ERROR, error=str(e))
                time.sleep(2 ** attempt)
            except (ValueError, KeyError, TypeError) as e:  # неожиданный формат ответа
                log.exception("%s вернул неожиданный ответ для %s", provider.name, ioc.value)
                return RepResult(provider.name, ioc.value, ioc.type.value, Verdict.ERROR,
                                 error=f"неожиданный ответ: {e.__class__.__name__}")
        raise AssertionError("unreachable")

    def check(self, iocs: Iterable[IOC], providers: Iterable[str] | None = None,
              progress: Callable[[int, int], None] | None = None) -> list[AggregatedResult]:
        """Проверить индикаторы во всех выбранных сервисах параллельно."""
        names = [n for n in (providers or self.available()) if n in self.providers]
        iocs = list(iocs)
        results: dict[tuple[str, str], list[RepResult]] = {(i.type.value, i.value): [] for i in iocs}
        jobs: list[tuple[str, IOC]] = []
        for i in iocs:
            reason = self._gate(i)
            if reason:
                results[(i.type.value, i.value)] = [RepResult(n, i.value, i.type.value, Verdict.SKIPPED, error=reason)
                                                    for n in names]
            elif "allowlisted" in i.tags:
                results[(i.type.value, i.value)] = [RepResult(n, i.value, i.type.value, Verdict.SKIPPED,
                                                              error="в allowlist") for n in names]
            else:
                jobs.extend((n, i) for n in names)

        done = 0
        with ThreadPoolExecutor(max_workers=max(1, self.settings.reputation.max_workers)) as pool:
            futures = {pool.submit(self._check_one, self.providers[n], i): i for n, i in jobs}
            for fut in as_completed(futures):
                i = futures[fut]
                results[(i.type.value, i.value)].append(fut.result())
                done += 1
                if progress:
                    progress(done, len(jobs))

        out = []
        for i in iocs:
            res = sorted(results[(i.type.value, i.value)], key=lambda r: names.index(r.provider)
                         if r.provider in names else 99)
            out.append(AggregatedResult(i.value, i.type.value, aggregate(res), res))
        return out

    def check_values(self, values: Iterable[tuple[IOCType, str]], **kw: Any) -> list[AggregatedResult]:
        """Проверить пары (тип, значение), сами определив внутренние адреса и домены."""
        from ..ioc.extractor import classify_ip, host_scope

        iocs = []
        for t, v in values:
            if t in (IOCType.IPV4, IOCType.IPV6):
                scope = classify_ip(v)
            elif t == IOCType.DOMAIN:
                scope = host_scope(v)
            else:
                scope = ""
            iocs.append(IOC(t, v, scope))
        return self.check(iocs, **kw)
