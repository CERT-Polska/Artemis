import time
from random import randrange
from typing import Any, Optional
from uuid import uuid4

from redis import Redis

from artemis.config import Config


class ResourceLock:
    def __init__(self, redis: Redis, res_name: str):  # type: ignore[type-arg]
        self.redis = redis
        self.res_name = res_name
        self.lid = str(uuid4())

    def acquire(self, expiry: Optional[int] = None) -> None:
        """
        Acquires a lock.

        If expiry is set, the lock will be set to expire after `expiry` seconds
        (so if expiry is 0, it won't even be acquired).
        """
        if expiry == 0:
            return

        while True:
            if self.redis.set(self.res_name, self.lid, nx=True, ex=expiry):
                return
            else:
                time.sleep(randrange(Config.LOCK_SLEEP_MIN_SECONDS, Config.LOCK_SLEEP_MAX_SECONDS))

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.redis.delete(self.res_name)
