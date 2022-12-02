from random import randint
from time import sleep
from types import TracebackType
from typing import Optional, Type
from uuid import uuid4

from redis import Redis


class ResourceLock:
    def __init__(self, redis: Redis, res_name: str):  # type: ignore[type-arg]
        self.redis = redis
        self.res_name = res_name
        self.lid = str(uuid4())

    def __enter__(self) -> None:
        while True:
            if lock := self.redis.get(self.res_name):
                if lock == self.lid:
                    return
                sleep(randint(1, 30))
            else:
                self.redis.set(self.res_name, self.lid, ex=15, nx=True)
                return

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.redis.delete(self.res_name)
