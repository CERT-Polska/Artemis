import os
import time
import unittest

from redis import Redis

REDIS_HOST = os.environ.get("TEST_REDIS_HOST")
REDIS_PORT = int(os.environ.get("TEST_REDIS_PORT", 6379))


@unittest.skipUnless(REDIS_HOST, "TEST_REDIS_HOST not set — skipping Redis integration tests")
class TestResourceLockIntegration(unittest.TestCase):
    """Integration tests that exercise the Lua scripts against a real Redis instance.

    These validate the core safety properties that unit-test mocks cannot cover:
    ownership-safe release, ownership-safe sustain, and no lock stealing after expiry.
    """

    SHORT_TTL = 2

    def setUp(self) -> None:
        self.redis = Redis(host=REDIS_HOST, port=REDIS_PORT, db=2)
        self.release_script = self.redis.register_script(
            """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
            """
        )
        self.sustain_script = self.redis.register_script(
            """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("expire", KEYS[1], ARGV[2])
            else
                return 0
            end
            """
        )

    def tearDown(self) -> None:
        self.redis.flushdb()

    def test_release_only_if_owner(self) -> None:
        """A holder cannot release a lock that was re-acquired by someone else."""
        key = "lock:integration:release-ownership"

        # Process A acquires
        self.redis.set(key, "process-A", nx=True, ex=self.SHORT_TTL)
        self.assertEqual(self.redis.get(key), b"process-A")

        # Simulate: lock expires and Process B re-acquires
        self.redis.set(key, "process-B")

        # Process A tries to release — must fail (returns 0, key untouched)
        result = self.release_script(keys=[key], args=["process-A"])
        self.assertEqual(result, 0)
        self.assertEqual(self.redis.get(key), b"process-B")

        # Process B releases — must succeed
        result = self.release_script(keys=[key], args=["process-B"])
        self.assertEqual(result, 1)
        self.assertIsNone(self.redis.get(key))

    def test_sustain_only_if_owner(self) -> None:
        """sustain must not refresh TTL if another process now holds the lock."""
        key = "lock:integration:sustain-ownership"

        # Process A acquires with short TTL
        self.redis.set(key, "process-A", nx=True, ex=self.SHORT_TTL)

        # Process A sustains — must succeed and extend TTL
        result = self.sustain_script(keys=[key], args=["process-A", 60])
        self.assertEqual(result, 1)
        self.assertGreater(self.redis.ttl(key), self.SHORT_TTL)

        # Simulate: lock re-acquired by B
        self.redis.set(key, "process-B")

        # Process A sustains — must fail
        result = self.sustain_script(keys=[key], args=["process-A", 60])
        self.assertEqual(result, 0)

    def test_no_lock_stealing_after_expiry(self) -> None:
        """After a lock expires, sustain/release from the old holder must be no-ops."""
        key = "lock:integration:expiry"

        # Process A acquires with very short TTL (500ms)
        self.redis.set(key, "process-A", nx=True, px=500)

        # Wait for expiration
        time.sleep(0.7)
        self.assertIsNone(self.redis.get(key))

        # Process B acquires
        self.redis.set(key, "process-B", nx=True, ex=self.SHORT_TTL)

        # Old holder A's release and sustain must both be no-ops
        self.assertEqual(self.release_script(keys=[key], args=["process-A"]), 0)
        self.assertEqual(self.sustain_script(keys=[key], args=["process-A", 60]), 0)

        # B's lock is untouched
        self.assertEqual(self.redis.get(key), b"process-B")


if __name__ == "__main__":
    unittest.main()
