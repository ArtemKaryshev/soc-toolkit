"""Потокобезопасный ограничитель частоты запросов (скользящее окно 60 секунд)."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.per_minute = max(1, per_minute)
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()
        self._clock = clock
        self._sleep = sleep

    def acquire(self, max_wait: float = 120.0) -> bool:
        """Дождаться слота. False, если ждать пришлось бы дольше max_wait."""
        while True:
            with self._lock:
                now = self._clock()
                while self._calls and now - self._calls[0] >= 60:
                    self._calls.popleft()
                if len(self._calls) < self.per_minute:
                    self._calls.append(now)
                    return True
                wait = 60 - (now - self._calls[0])
            if wait > max_wait:
                return False
            self._sleep(min(wait, 1.0) + 0.01)
