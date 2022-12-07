import asyncio
import time
from random import randrange
from typing import Any, Optional
from uuid import uuid4

from redis import Redis
from redis.asyncio import Redis as AsyncRedis

LOCK_SLEEP_MIN_SECONDS = 1
LOCK_SLEEP_MAX_SECONDS = 5


class ResourceLock:
    def __init__(self, redis: Redis, res_name: str):  # type: ignore[type-arg]
        self.redis = redis
        self.res_name = res_name
        self.lid = str(uuid4())

    def acquire(self, expiry: Optional[int] = None) -> None:
        if expiry == 0:
            return

        while True:
            if self.redis.set(self.res_name, self.lid, nx=True, ex=expiry):
                return
            else:
                time.sleep(randrange(LOCK_SLEEP_MIN_SECONDS, LOCK_SLEEP_MAX_SECONDS))

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.redis.delete(self.res_name)


class AsyncResourceLock:
    def __init__(self, redis: AsyncRedis, res_name: str):  # type: ignore[type-arg]
        self.redis = redis
        self.res_name = res_name
        self.lid = str(uuid4())

    async def acquire(self, expiry: Optional[int] = None) -> None:
        if expiry == 0:
            return

        while True:
            if await self.redis.set(self.res_name, self.lid, nx=True, ex=expiry):
                return
            else:
                await asyncio.sleep(randrange(LOCK_SLEEP_MIN_SECONDS, LOCK_SLEEP_MAX_SECONDS))

    async def __enter__(self) -> None:
        await self.acquire()

    async def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.redis.delete(self.res_name)
