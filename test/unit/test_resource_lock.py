import logging
import threading
import unittest
from typing import Any, Dict, List, Tuple
from unittest import mock

from artemis.resource_lock import (
    LOCKS_TO_SUSTAIN,
    LOCKS_TO_SUSTAIN_LOCK,
    FailedToAcquireLockException,
    ResourceLock,
)


class FakeRedis:
    """Minimal dict-backed Redis implementing only the semantics ResourceLock uses:
    SET (with optional NX and EX), GET, DEL, and EVAL of the compare-and-delete /
    compare-and-set Lua scripts. This lets ownership-transfer scenarios be tested
    deterministically without a live Redis."""

    _COMPARE_AND_DELETE = (
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
    )
    _COMPARE_AND_SET = (
        "if redis.call('get', KEYS[1]) == ARGV[1] then "
        "return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end"
    )

    def __init__(self) -> None:
        self.data: Dict[str, str] = {}
        self.eval_calls: List[Tuple[str, int, str, Tuple[Any, ...]]] = []

    def set(self, key: str, value: str, nx: bool = False, ex: Any = None) -> Any:
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    def get(self, key: str) -> Any:
        return self.data.get(key)

    def delete(self, *keys: str) -> int:
        deleted = 0
        for key in keys:
            if key in self.data:
                del self.data[key]
                deleted += 1
        return deleted

    def eval(self, script: str, numkeys: int, key: str, *args: Any) -> Any:
        self.eval_calls.append((script, numkeys, key, args))
        if script == self._COMPARE_AND_DELETE:
            if self.data.get(key) == args[0]:
                del self.data[key]
                return 1
            return 0
        if script == self._COMPARE_AND_SET:
            if self.data.get(key) == args[0]:
                # expiry is not modeled - ownership comparison is what matters here
                return 1
            return 0
        raise ValueError("Unsupported script in FakeRedis")

    def is_locked(self, key: str) -> bool:
        return key in self.data


class TestReleaseAllLocks(unittest.TestCase):
    """Tests for ResourceLock.release_all_locks - the safety-net method called
    at the start of every worker iteration to clean up leaked locks."""

    def setUp(self) -> None:
        # Clean state before each test
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.logger = logging.getLogger("test_resource_lock")
        self.redis = FakeRedis()

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    def test_release_all_locks_deletes_redis_keys(self) -> None:
        """release_all_locks must delete every held lock from Redis (owner-checked)."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-1.2.3.4"] = "uuid-1"
            LOCKS_TO_SUSTAIN["lock-5.6.7.8"] = "uuid-2"
        self.redis.set("lock-1.2.3.4", "uuid-1")
        self.redis.set("lock-5.6.7.8", "uuid-2")

        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            ResourceLock.release_all_locks(self.logger)

        self.assertEqual(self.redis.data, {})

    def test_release_all_locks_clears_sustain_dict(self) -> None:
        """After release_all_locks, LOCKS_TO_SUSTAIN must be empty so the
        heartbeat thread stops refreshing the deleted keys."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-target-a"] = "uuid-a"
            LOCKS_TO_SUSTAIN["lock-target-b"] = "uuid-b"

        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            ResourceLock.release_all_locks(self.logger)

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

    def test_release_all_locks_noop_when_empty(self) -> None:
        """Calling release_all_locks with no held locks must not raise."""
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            ResourceLock.release_all_locks(self.logger)

        self.assertEqual(self.redis.eval_calls, [])
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

    def test_acquire_then_release_all_cleans_up(self) -> None:
        """Simulates a lock leak: acquire a lock, then call release_all_locks
        instead of the normal release path. The lock must be fully cleaned up."""
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            lock = ResourceLock("lock-leaked-target", max_tries=1)
            lock.acquire()

            with LOCKS_TO_SUSTAIN_LOCK:
                self.assertIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

            ResourceLock.release_all_locks(self.logger)

        self.assertFalse(self.redis.is_locked("lock-leaked-target"))
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

    def test_release_all_locks_is_thread_safe(self) -> None:
        """release_all_locks must not corrupt state when called concurrently
        with lock acquire/release on other threads."""
        errors: List[Exception] = []

        def acquire_and_release() -> None:
            try:
                for i in range(20):
                    lock = ResourceLock(f"lock-thread-{threading.current_thread().name}-{i}", max_tries=1)
                    lock.acquire()
                    lock.release()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        def release_all_repeatedly() -> None:
            try:
                for _ in range(20):
                    ResourceLock.release_all_locks(self.logger)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [
            threading.Thread(target=acquire_and_release),
            threading.Thread(target=acquire_and_release),
            threading.Thread(target=release_all_repeatedly),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"Thread safety errors: {errors}")


class TestResourceLockBasics(unittest.TestCase):
    """Verify that normal acquire/release still works correctly after the fix."""

    def setUp(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.redis = FakeRedis()

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    def test_acquire_adds_to_sustain_dict(self) -> None:
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            lock = ResourceLock("lock-test-target", max_tries=1)
            lock.acquire()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertIn("lock-test-target", LOCKS_TO_SUSTAIN)

    def test_release_removes_from_sustain_dict_and_redis(self) -> None:
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            lock = ResourceLock("lock-test-target", max_tries=1)
            lock.acquire()
            lock.release()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-test-target", LOCKS_TO_SUSTAIN)
        self.assertFalse(self.redis.is_locked("lock-test-target"))

    def test_failed_acquire_raises(self) -> None:
        self.redis.set("lock-contended", "some-other-owner")

        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            lock = ResourceLock("lock-contended", max_tries=1)

            with self.assertRaises(FailedToAcquireLockException):
                lock.acquire()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-contended", LOCKS_TO_SUSTAIN)

    def test_context_manager_releases_on_exit(self) -> None:
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            with ResourceLock("lock-ctx", max_tries=1):
                with LOCKS_TO_SUSTAIN_LOCK:
                    self.assertIn("lock-ctx", LOCKS_TO_SUSTAIN)

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-ctx", LOCKS_TO_SUSTAIN)
        self.assertFalse(self.redis.is_locked("lock-ctx"))


class TestOwnershipCheckedRelease(unittest.TestCase):
    """The core regression tests: a release must never delete a lock that is
    now owned by a different holder."""

    def setUp(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.redis = FakeRedis()

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    def test_stray_release_does_not_delete_another_holders_lock(self) -> None:
        """A's release-after-release (or the WAF-skip path creating a fresh lock
        object for the same resource) must not destroy B's lock."""
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            lock_a = ResourceLock("lock-shared-target", max_tries=1)
            lock_a.acquire()
            lock_a.release()

            # B acquires the now-free lock
            lock_b = ResourceLock("lock-shared-target", max_tries=1)
            lock_b.acquire()
            self.assertTrue(self.redis.is_locked("lock-shared-target"))

            # A's stray/double release must be a no-op
            lock_a.release()
            self.assertTrue(self.redis.is_locked("lock-shared-target"))

            # And a third holder must still be refused
            with self.assertRaises(FailedToAcquireLockException):
                ResourceLock("lock-shared-target", max_tries=1).acquire()

            # B releases correctly
            lock_b.release()
            self.assertFalse(self.redis.is_locked("lock-shared-target"))

    def test_fresh_lock_object_with_same_name_cannot_release(self) -> None:
        """Simulates check_connection_to_base_url_and_save_error(): a fresh
        ResourceLock instance (different lid) for the same resource must not be
        able to release the lock held by the original owner."""
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            owner = ResourceLock("lock-scan-destination", max_tries=1)
            owner.acquire()

            fresh = ResourceLock("lock-scan-destination", max_tries=1)
            fresh.release()

            self.assertTrue(self.redis.is_locked("lock-scan-destination"))

    def test_owner_release_after_sustain_refresh_still_works(self) -> None:
        """The heartbeat refreshes the key with the owner's lid; the owner must
        still be able to release afterwards."""
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            lock = ResourceLock("lock-refreshed", max_tries=1)
            lock.acquire()

            # simulate the sustain thread refreshing ownership
            self.redis.set("lock-refreshed", lock.lid)

            lock.release()
            self.assertFalse(self.redis.is_locked("lock-refreshed"))

    def test_release_all_locks_cannot_delete_foreign_lock(self) -> None:
        """Even if a foreign lid somehow lands in LOCKS_TO_SUSTAIN (e.g. a stale
        entry from a previous process state), release_all_locks must not delete
        a key owned by someone else."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-foreign"] = "stale-uuid"
        self.redis.set("lock-foreign", "actual-owner-uuid")

        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            ResourceLock.release_all_locks(logging.getLogger("test"))

        self.assertTrue(self.redis.is_locked("lock-foreign"))


class TestSustainOwnership(unittest.TestCase):
    """The heartbeat must not overwrite another process's lock ownership."""

    def setUp(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.redis = FakeRedis()

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    def test_compare_and_set_does_not_overwrite_foreign_owner(self) -> None:
        from artemis.resource_lock import _compare_and_set

        self.redis.set("lock-held", "actual-owner")
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            self.assertFalse(_compare_and_set("lock-held", "stale-lid", 60))
        self.assertEqual(self.redis.get("lock-held"), "actual-owner")

    def test_compare_and_set_succeeds_for_owner(self) -> None:
        from artemis.resource_lock import _compare_and_set

        self.redis.set("lock-held", "my-lid")
        with mock.patch("artemis.resource_lock.REDIS", self.redis):
            self.assertTrue(_compare_and_set("lock-held", "my-lid", 60))
        self.assertEqual(self.redis.get("lock-held"), "my-lid")


if __name__ == "__main__":
    unittest.main()
