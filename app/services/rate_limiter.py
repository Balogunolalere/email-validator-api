import asyncio
from collections import deque
from time import time


class SlidingWindowRateLimiter:
    """Async-safe sliding-window rate limiter.

    Allows up to ``rate_limit`` acquisitions within each ``window_size``
    second window.  Uses a lock to prevent races between coroutines and
    an iterative retry loop (no recursion) so it can never blow the
    call stack under sustained load.
    """

    def __init__(self, rate_limit: int, window_size: float = 1.0):
        self.rate_limit = rate_limit
        self.window_size = window_size
        self.timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time()
                # Purge timestamps outside the current window
                while self.timestamps and self.timestamps[0] <= now - self.window_size:
                    self.timestamps.popleft()

                if len(self.timestamps) < self.rate_limit:
                    self.timestamps.append(now)
                    return  # slot acquired

            # Window is full — yield and retry
            await asyncio.sleep(0.01)
