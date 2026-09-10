from typing import Any, List, Optional

from redis import Redis

# Escapes Redis glob metacharacters so cache names are always matched literally.
# Note: unlike fnmatch/Tcl, Redis treats [] as an empty (never-matching) class,
# so ] must be escaped as \] rather than []]. Verified against real Redis.
_GLOB_ESCAPE_TABLE = {
    ord("*"): "[*]",
    ord("?"): "[?]",
    ord("["): "[[]",
    ord("]"): "\\]",
    ord("\\"): "\\\\",
}


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
        # Delete only this cache's keys. Never flushall()/flushdb() here: Karton
        # queues, locks, and other caches share the same Redis instance/database,
        # so flushdb would be equally destructive.
        safe_name = self.cache_name.translate(_GLOB_ESCAPE_TABLE)
        batch: List[Any] = []
        for key in self.redis.scan_iter(match=f"{safe_name}:*", count=1000):
            batch.append(key)
            if len(batch) >= 1000:
                self.redis.delete(*batch)
                batch = []
        if batch:
            self.redis.delete(*batch)
