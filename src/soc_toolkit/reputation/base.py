"""Базовые типы для провайдеров репутации."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, ClassVar

import requests

from ..ioc import IOCType


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"      # сервис ничего не знает об индикаторе
    ERROR = "error"
    SKIPPED = "skipped"      # не отправлялся (политика, нет ключа, тип не поддерживается)

    @property
    def weight(self) -> int:
        return {"malicious": 4, "suspicious": 3, "clean": 1, "unknown": 0, "error": -1, "skipped": -2}[self.value]

    @property
    def icon(self) -> str:
        return {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢", "unknown": "⚪", "error": "⚠️",
                "skipped": "⏭️"}[self.value]


@dataclass
class RepResult:
    provider: str
    indicator: str
    ioc_type: str
    verdict: Verdict
    score: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    link: str = ""
    cached: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RepResult:
        return cls(**{**d, "verdict": Verdict(d["verdict"])})


class ProviderError(Exception):
    """Ошибка провайдера с понятным пользователю текстом."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class Provider(ABC):
    name: ClassVar[str]
    title: ClassVar[str]
    supported: ClassVar[frozenset[IOCType]]
    requires_key: ClassVar[bool] = True
    signup_url: ClassVar[str] = ""

    def __init__(self, session: requests.Session, api_key: str = "", timeout: float = 15.0):
        self.session = session
        self.api_key = api_key
        self.timeout = timeout

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported

    def _get(self, url: str, **kw: Any) -> requests.Response:
        return self._request("GET", url, **kw)

    def _request(self, method: str, url: str, **kw: Any) -> requests.Response:
        try:
            r = self.session.request(method, url, timeout=self.timeout, **kw)
        except requests.Timeout as e:
            raise ProviderError("таймаут", retryable=True) from e
        except requests.ConnectionError as e:
            raise ProviderError("нет соединения (проверьте прокси/интернет)", retryable=True) from e
        if r.status_code in (401, 403):
            raise ProviderError(f"HTTP {r.status_code}: неверный ключ или нет доступа")
        if r.status_code == 429:
            raise ProviderError("HTTP 429: превышен лимит запросов", retryable=True)
        if r.status_code >= 500:
            raise ProviderError(f"HTTP {r.status_code}: ошибка сервиса", retryable=True)
        return r

    @abstractmethod
    def check(self, ioc_type: IOCType, value: str) -> RepResult:
        """Проверить индикатор. Бросает ProviderError при ошибке."""

    def result(self, ioc_type: IOCType, value: str, verdict: Verdict, **kw: Any) -> RepResult:
        return RepResult(self.name, value, ioc_type.value, verdict, **kw)
