from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Token-bucket limiter shared by all tool executions."""

    def __init__(self, rate: float = 10.0, concurrency: int = 5):
        self.rate = rate
        self._interval = 1.0 / rate if rate > 0 else 0
        self._sem = asyncio.Semaphore(concurrency)
        self._last: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        await self._sem.acquire()
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    def release(self) -> None:
        self._sem.release()
