import os
import unittest
from uuid import uuid4

from redis import Redis

REDIS_CONN_STR = os.environ.get("REDIS_CONN_STR")

RELEASE_LOCK_SCRIPT_SRC = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""

SUSTAIN_LOCK_SCRIPT_SRC = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("expire", KEYS[1], ARGV[2])
else
    return 0
end
"""


@unittest.skipUnless(REDIS_CONN_STR, "REDIS_CONN_STR not set — skipping lock e2e tests")
class TestResourceLockE2E(unittest.TestCase):
    """E2E tests verifying that lock ownership is enforced against a real Redis instance.

    These simulate the scenario where a worker's lock expires and another worker
    re-acquires it, ensuring the original worker cannot release or sustain the lock.
    """

    LOCK_KEY = "lock:e2e:ownership-test"
    SHORT_TTL = 5

    def setUp(self) -> None:
        self.redis = Redis.from_url(REDIS_CONN_STR)  # type: ignore[arg-type]
        self.release_script = self.redis.register_script(RELEASE_LOCK_SCRIPT_SRC)
        self.sustain_script = self.redis.register_script(SUSTAIN_LOCK_SCRIPT_SRC)
        self.redis.delete(self.LOCK_KEY)

    def tearDown(self) -> None:
        self.redis.delete(self.LOCK_KEY)

    def test_release_fails_after_lock_reacquired_by_another_worker(self) -> None:
        """Worker A's lock expires, Worker B acquires it — Worker A's release must not affect B."""
        worker_a_id = str(uuid4())
        worker_b_id = str(uuid4())

        # Worker A acquires
        self.redis.set(self.LOCK_KEY, worker_a_id, nx=True, ex=self.SHORT_TTL)
        self.assertEqual(self.redis.get(self.LOCK_KEY), worker_a_id.encode())

        # Simulate expiry + Worker B re-acquires
        self.redis.delete(self.LOCK_KEY)
        self.redis.set(self.LOCK_KEY, worker_b_id, nx=True, ex=self.SHORT_TTL)

        # Worker A tries to release — must be a no-op
        result = self.release_script(keys=[self.LOCK_KEY], args=[worker_a_id])
        self.assertEqual(result, 0)

        # Worker B's lock must still be held
        self.assertEqual(self.redis.get(self.LOCK_KEY), worker_b_id.encode())

    def test_sustain_fails_after_lock_reacquired_by_another_worker(self) -> None:
        """Worker A's lock expires, Worker B acquires it — Worker A's sustain must not refresh B's TTL."""
        worker_a_id = str(uuid4())
        worker_b_id = str(uuid4())

        # Worker A acquires
        self.redis.set(self.LOCK_KEY, worker_a_id, nx=True, ex=self.SHORT_TTL)

        # Simulate expiry + Worker B re-acquires with short TTL
        self.redis.delete(self.LOCK_KEY)
        self.redis.set(self.LOCK_KEY, worker_b_id, nx=True, ex=self.SHORT_TTL)

        # Worker A tries to sustain with a long TTL — must fail
        result = self.sustain_script(keys=[self.LOCK_KEY], args=[worker_a_id, 300])
        self.assertEqual(result, 0)

        # B's TTL must remain short (not bumped to 300)
        ttl = self.redis.ttl(self.LOCK_KEY)
        self.assertLessEqual(ttl, self.SHORT_TTL)
        self.assertEqual(self.redis.get(self.LOCK_KEY), worker_b_id.encode())


if __name__ == "__main__":
    unittest.main()
