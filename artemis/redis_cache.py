from typing import Optional

from redis import Redis


class RedisCache:
    def __init__(self, redis: Redis, cache_name: str, duration: int = 24 * 60 * 60):  # type: ignore[type-arg]
        """
        duration: in seconds, by default 24h
        """
        self.redis = redis
        self.duration = duration
        self.cache_name = f"cache.{cache_name}"

    def get(self, key: str) -> Optional[bytes]:
        return self.redis.get(f"{self.cache_name}:{key}")

    def set(self, key: str, value: bytes, timeout: Optional[int] = None) -> None:
        if not timeout:
            timeout = self.duration
        self.redis.set(f"{self.cache_name}:{key}", value, ex=timeout)

    def flush(self) -> None:
        self.redis.flushall()
