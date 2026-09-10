import unittest
from typing import Any, Dict, List, Optional, Tuple

from artemis.redis_cache import RedisCache


def redis_glob_match(name: bytes, pattern: bytes) -> bool:
    """Match bytes against a Redis glob pattern, mirroring Redis stringmatchlen
    semantics (which differ from fnmatch in edge cases - e.g. Redis treats []
    as an empty, never-matching class, so fnmatch must NOT be used here)."""

    def match(si: int, pi: int) -> bool:
        while pi < len(pattern):
            c = pattern[pi : pi + 1]
            if c == b"*":
                while pi < len(pattern) and pattern[pi : pi + 1] == b"*":
                    pi += 1
                if pi == len(pattern):
                    return True
                for skip in range(si, len(name) + 1):
                    if match(skip, pi):
                        return True
                return False
            if si >= len(name):
                return False
            if c == b"?":
                si += 1
                pi += 1
            elif c == b"\\":
                pi += 1
                if pi >= len(pattern) or name[si : si + 1] != pattern[pi : pi + 1]:
                    return False
                si += 1
                pi += 1
            elif c == b"[":
                pi += 1
                negate = pi < len(pattern) and pattern[pi : pi + 1] == b"^"
                if negate:
                    pi += 1
                found = False
                while True:
                    if pi >= len(pattern):
                        return False
                    if pattern[pi : pi + 1] == b"]":
                        # No first-position exception (unlike fnmatch): in Redis,
                        # [] is an empty, never-matching class.
                        pi += 1
                        break
                    if pattern[pi : pi + 1] == b"\\" and pi + 1 < len(pattern):
                        pi += 1
                    lo = pattern[pi : pi + 1]
                    pi += 1
                    if pi + 1 < len(pattern) and pattern[pi : pi + 1] == b"-":
                        pi += 1
                        if pattern[pi : pi + 1] == b"\\" and pi + 1 < len(pattern):
                            pi += 1
                        hi = pattern[pi : pi + 1]
                        pi += 1
                        if lo <= name[si : si + 1] <= hi:
                            found = True
                    elif name[si : si + 1] == lo:
                        found = True
                if found == negate:
                    return False
                si += 1
            else:
                if name[si : si + 1] != c:
                    return False
                si += 1
                pi += 1
        return si == len(name)

    return match(0, 0)


class FakeRedis:
    """Minimal dict-backed Redis implementing only what RedisCache uses:
    SET (with EX), GET, SCAN-iteration and batched DEL.

    Keys are stored as bytes to mirror production, where no client sets
    decode_responses - patterns are therefore matched against bytes too."""

    def __init__(self) -> None:
        self.data: Dict[bytes, bytes] = {}
        self.delete_calls: List[Tuple[bytes, ...]] = []

    def set(self, key: str, value: bytes, ex: Optional[int] = None) -> bool:
        self.data[key.encode() if isinstance(key, str) else key] = value
        return True

    def get(self, key: str) -> Optional[bytes]:
        return self.data.get(key.encode() if isinstance(key, str) else key)

    def scan_iter(self, match: Optional[str] = None, count: Optional[int] = None) -> Any:
        pattern = match.encode() if isinstance(match, str) else match
        for key in list(self.data.keys()):
            if pattern is None or redis_glob_match(key, pattern):
                yield key

    def delete(self, *keys: bytes) -> int:
        self.delete_calls.append(keys)
        deleted = 0
        for key in keys:
            if key in self.data:
                del self.data[key]
                deleted += 1
        return deleted

    def has(self, key: str) -> bool:
        raw = key.encode() if isinstance(key, str) else key
        return raw in self.data


class RedisCacheFlushTest(unittest.TestCase):
    def setUp(self) -> None:
        self.redis = FakeRedis()

    def _cache(self, name: str, **kwargs: Any) -> RedisCache:
        return RedisCache(self.redis, name, **kwargs)  # type: ignore[arg-type]

    def test_flush_deletes_only_this_caches_keys(self) -> None:
        """flush() must remove cache.modA:* while Karton queues, locks,
        counters and other caches sharing the instance survive."""
        cache = self._cache("modA")
        other = self._cache("modB")
        cache.set("k1", b"v1")
        cache.set("k2", b"v2")
        other.set("k1", b"other")
        self.redis.set("karton.queue.classifier:abc", b"task")
        self.redis.set("lock-1.2.3.4", b"owner-lid")
        self.redis.set("analysis-num-finished-tasks-xyz", b"3")

        cache.flush()

        self.assertFalse(self.redis.has("cache.modA:k1"))
        self.assertFalse(self.redis.has("cache.modA:k2"))
        self.assertTrue(self.redis.has("cache.modB:k1"))
        self.assertTrue(self.redis.has("karton.queue.classifier:abc"))
        self.assertTrue(self.redis.has("lock-1.2.3.4"))
        self.assertTrue(self.redis.has("analysis-num-finished-tasks-xyz"))
        self.assertEqual(self.redis.get("cache.modB:k1"), b"other")

    def test_flush_on_empty_cache_issues_no_deletes(self) -> None:
        cache = self._cache("empty")

        cache.flush()

        self.assertEqual(self.redis.delete_calls, [])

    def test_flush_matches_cache_name_literally(self) -> None:
        """Glob metacharacters in a cache name must not match foreign keys."""
        cache = self._cache("mo[d]x?\\y")
        self.redis.set("cache.mo[d]x?\\y:k", b"mine")
        self.redis.set("cache.modx:k", b"foreign")
        self.redis.set("cache.mody:k", b"foreign")
        self.redis.set("cache.mod:k", b"foreign")

        cache.flush()

        self.assertFalse(self.redis.has("cache.mo[d]x?\\y:k"))
        self.assertTrue(self.redis.has("cache.modx:k"))
        self.assertTrue(self.redis.has("cache.mody:k"))
        self.assertTrue(self.redis.has("cache.mod:k"))

    def test_get_set_roundtrip_with_timeout(self) -> None:
        """The untouched contract: get/set still work, with the default TTL path."""
        cache = self._cache("modA", duration=60)

        cache.set("k", b"v")
        self.assertEqual(cache.get("k"), b"v")
        self.assertIsNone(cache.get("missing"))


if __name__ == "__main__":
    unittest.main()
