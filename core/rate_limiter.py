"""Per-source asynchronous rate limiter."""

from __future__ import annotations

import asyncio


class AsyncRateLimiter:
    """Simple async rate limiter with per-instance request spacing."""

    def __init__(self, delay_seconds: float) -> None:
        """Initialize limiter.

        Args:
            delay_seconds: Minimum interval between consecutive requests.
        """

        self.delay_seconds = delay_seconds
        self.last_request_time: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission for the next request respecting delay interval."""

        async with self._lock:
            now = asyncio.get_running_loop().time()
            elapsed = now - self.last_request_time
            if elapsed < self.delay_seconds:
                await asyncio.sleep(self.delay_seconds - elapsed)
                now = asyncio.get_running_loop().time()
            self.last_request_time = now
