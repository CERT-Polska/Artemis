import time
from random import uniform
from typing import Any, Optional
from uuid import uuid4

from redis import Redis

from artemis.config import Config


class FailedToAcquireLockException(Exception):
    """
    Used to indicate a lock that was not acquired in max_tries attempts.
    """


class ResourceLock:
    def __init__(self, redis: Redis, res_name: str, max_tries: Optional[int] = None):  # type: ignore[type-arg]
        self.redis = redis
        self.res_name = res_name
        self.lid = str(uuid4())
        self.max_tries = max_tries

    def acquire(
        self, expiry: Optional[int] = Config.DEFAULT_LOCK_EXPIRY_SECONDS
    ) -> None:
        """
        Acquires a lock.

        If expiry is set, the lock will be set to expire after `expiry` seconds
        (so if expiry is 0, it won't even be acquired). If it is not set, the lock
        will expire after Config.DEFAULT_LOCK_EXPIRY_SECONDS seconds.
        """
        if expiry == 0:
            return

        attempts = 0
        while self.max_tries is None or attempts < self.max_tries:
            if self.redis.set(self.res_name, self.lid, nx=True, ex=expiry):
                return

            attempts += 1
            time.sleep(
                uniform(Config.LOCK_SLEEP_MIN_SECONDS, Config.LOCK_SLEEP_MAX_SECONDS)
            )

        raise FailedToAcquireLockException()

    def release(self) -> None:
        self.redis.delete(self.res_name)

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()
