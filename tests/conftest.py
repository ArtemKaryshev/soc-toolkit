from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Каждый тест работает в своей домашней папке и без ключей из окружения."""
    monkeypatch.setenv("SOC_TOOLKIT_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SOC_TOOLKIT_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    for var in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "ABUSECH_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


@pytest.fixture
def samples() -> Path:
    return SAMPLES


class FakeResponse:
    def __init__(self, status: int = 200, payload: Any = None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> Any:
        return self._payload

    @property
    def text(self) -> str:
        return json.dumps(self._payload)


class FakeSession:
    """Подмена requests.Session: отвечает по подстроке URL и запоминает запросы."""

    def __init__(self, routes: dict[str, FakeResponse | Exception]):
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.headers: dict[str, str] = {}
        self.proxies: dict[str, str] = {}
        self.verify = True

    def request(self, method: str, url: str, **kw: Any) -> FakeResponse:
        self.calls.append((method, url, kw))
        for part, resp in self.routes.items():
            if part in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(404, {})


@pytest.fixture
def fake_session():
    return FakeSession
