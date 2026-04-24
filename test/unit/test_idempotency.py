import time
import unittest
from typing import Any, Dict, Optional

from artemis.idempotency import IdempotencyStore


class _FakeRedis:
    """Minimal in-memory redis replacement covering only the ops IdempotencyStore uses."""

    def __init__(self) -> None:
        self._store: Dict[str, bytes] = {}
        self._expiry: Dict[str, float] = {}

    def _gc(self, key: str) -> None:
        exp = self._expiry.get(key)
        if exp is not None and exp < time.monotonic():
            self._store.pop(key, None)
            self._expiry.pop(key, None)

    def set(self, key: str, value: Any, nx: bool = False, px: Optional[int] = None) -> bool:
        self._gc(key)
        if nx and key in self._store:
            return False
        self._store[key] = value.encode() if isinstance(value, str) else value
        if px is not None:
            self._expiry[key] = time.monotonic() + px / 1000.0
        else:
            self._expiry.pop(key, None)
        return True

    def get(self, key: str) -> Optional[bytes]:
        self._gc(key)
        return self._store.get(key)

    def delete(self, key: str) -> int:
        existed = key in self._store
        self._store.pop(key, None)
        self._expiry.pop(key, None)
        return 1 if existed else 0


class IdempotencyStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.redis = _FakeRedis()
        self.store = IdempotencyStore(self.redis)  # type: ignore[arg-type]
        self.token = "secret-token"
        self.body = {"targets": ["example.com"], "priority": "normal"}

    def test_first_call_is_new(self) -> None:
        state, cached = self.store.begin(self.token, "k1", self.body)
        self.assertEqual(state, "new")
        self.assertIsNone(cached)

    def test_same_body_in_flight_returns_in_flight(self) -> None:
        self.store.begin(self.token, "k1", self.body)
        state, _ = self.store.begin(self.token, "k1", self.body)
        self.assertEqual(state, "in_flight")

    def test_replay_after_finalize(self) -> None:
        self.store.begin(self.token, "k1", self.body)
        response = {"ok": True, "ids": ["abc"]}
        self.store.finalize(self.token, "k1", self.body, response)
        state, cached = self.store.begin(self.token, "k1", self.body)
        self.assertEqual(state, "replay")
        self.assertEqual(cached, response)

    def test_conflict_on_different_body(self) -> None:
        self.store.begin(self.token, "k1", self.body)
        self.store.finalize(self.token, "k1", self.body, {"ok": True, "ids": []})
        state, cached = self.store.begin(self.token, "k1", {"targets": ["other.com"]})
        self.assertEqual(state, "conflict")
        self.assertIsNone(cached)

    def test_abort_allows_retry(self) -> None:
        self.store.begin(self.token, "k1", self.body)
        self.store.abort(self.token, "k1")
        state, _ = self.store.begin(self.token, "k1", self.body)
        self.assertEqual(state, "new")

    def test_keys_namespaced_per_token(self) -> None:
        self.store.begin("token-a", "k1", self.body)
        self.store.finalize("token-a", "k1", self.body, {"ok": True, "ids": ["a"]})
        state, _ = self.store.begin("token-b", "k1", self.body)
        self.assertEqual(state, "new")

    def test_body_field_order_does_not_affect_hash(self) -> None:
        self.store.begin(self.token, "k1", {"a": 1, "b": 2})
        self.store.finalize(self.token, "k1", {"a": 1, "b": 2}, {"ok": True})
        state, cached = self.store.begin(self.token, "k1", {"b": 2, "a": 1})
        self.assertEqual(state, "replay")
        self.assertEqual(cached, {"ok": True})


if __name__ == "__main__":
    unittest.main()
