from typing import Deque
from collections import deque
from time import time
import asyncio

class SlidingWindowRateLimiter:
    def __init__(self, rate_limit: int, window_size: int = 1):
        self.rate_limit = rate_limit
        self.window_size = window_size
        self.timestamps = deque()

    async def acquire(self):
        current_time = time()
        while self.timestamps and self.timestamps[0] <= current_time - self.window_size:
            self.timestamps.popleft()

        if len(self.timestamps) < self.rate_limit:
            self.timestamps.append(current_time)
            return
        else:
            await asyncio.sleep(0.01)
            await self.acquire()