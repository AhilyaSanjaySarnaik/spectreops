"""Engagement-wide request rate limiting.

`scope.rate_limit` is a requests/second ceiling and `scope.concurrency` a cap on
in-flight requests, so the limiter has to sit at *request* granularity — one
dir_brute call can issue dozens of requests. The Executor installs the
engagement limiter into a context variable for the duration of each tool call;
HTTP tools take a slot per request, and subprocess tools (nmap, nuclei) read
`rate`/`concurrency` to pass equivalent flags.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar


class RateLimiter:
    """Evenly spaced requests (rate/sec) with at most `concurrency` in flight."""

    def __init__(self, rate: float = 10.0, concurrency: int = 5):
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self.rate = rate
        self.concurrency = concurrency
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._sem = asyncio.Semaphore(concurrency)
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def _space(self) -> None:
        if not self._interval:
            return
        async with self._lock:          # serialise slot hand-out so spacing holds
            now = time.monotonic()
            if self._next > now:
                await asyncio.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + self._interval

    async def acquire(self) -> None:
        """Take a slot manually; pair with release(). Prefer `async with slot()`."""
        await self._sem.acquire()
        try:
            await self._space()
        except BaseException:
            self._sem.release()
            raise

    def release(self) -> None:
        self._sem.release()

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Hold one request slot: `async with limiter.slot(): await client.get(...)`."""
        async with self._sem:
            await self._space()
            yield


UNLIMITED = RateLimiter(rate=0, concurrency=10_000)
_current: ContextVar[RateLimiter] = ContextVar("spectreops_rate_limiter", default=UNLIMITED)


def current_limiter() -> RateLimiter:
    return _current.get()


def use_limiter(limiter: RateLimiter):
    """Install `limiter` for the current context; returns a token for reset()."""
    return _current.set(limiter)


def reset_limiter(token) -> None:
    _current.reset(token)
