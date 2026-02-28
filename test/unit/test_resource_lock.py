import logging
import threading
import unittest
from unittest.mock import MagicMock, patch

from artemis.resource_lock import (
    LOCKS_TO_SUSTAIN,
    LOCKS_TO_SUSTAIN_LOCK,
    FailedToAcquireLockException,
    ResourceLock,
)


class TestReleaseAllLocks(unittest.TestCase):
    """Tests for ResourceLock.release_all_locks — the safety-net method called
    at the start of every worker iteration to clean up leaked locks."""

    def setUp(self) -> None:
        # Clean state before each test
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.logger = logging.getLogger("test_resource_lock")

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    def test_release_all_locks_deletes_redis_keys(self, mock_script: MagicMock) -> None:
        """release_all_locks must call the release script for every held lock."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-1.2.3.4"] = "uuid-1"
            LOCKS_TO_SUSTAIN["lock-5.6.7.8"] = "uuid-2"

        ResourceLock.release_all_locks(self.logger)

        mock_script.assert_any_call(keys=["lock-1.2.3.4"], args=["uuid-1"])
        mock_script.assert_any_call(keys=["lock-5.6.7.8"], args=["uuid-2"])
        self.assertEqual(mock_script.call_count, 2)

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    def test_release_all_locks_clears_sustain_dict(self, mock_script: MagicMock) -> None:
        """After release_all_locks, LOCKS_TO_SUSTAIN must be empty so the
        heartbeat thread stops refreshing the deleted keys."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-target-a"] = "uuid-a"
            LOCKS_TO_SUSTAIN["lock-target-b"] = "uuid-b"

        ResourceLock.release_all_locks(self.logger)

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    def test_release_all_locks_noop_when_empty(self, mock_script: MagicMock) -> None:
        """Calling release_all_locks with no held locks must not raise."""
        ResourceLock.release_all_locks(self.logger)

        mock_script.assert_not_called()
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    @patch("artemis.resource_lock.REDIS")
    def test_acquire_then_release_all_cleans_up(self, mock_redis: MagicMock, mock_script: MagicMock) -> None:
        """Simulates a lock leak: acquire a lock, then call release_all_locks
        instead of the normal release path. The lock must be fully cleaned up."""
        mock_redis.set.return_value = True  # simulate successful SET NX

        lock = ResourceLock("lock-leaked-target", max_tries=1)
        lock.acquire()

        # Verify the lock is tracked
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertIn("lock-leaked-target", LOCKS_TO_SUSTAIN)
            lid = LOCKS_TO_SUSTAIN["lock-leaked-target"]

        # Simulate the safety-net cleanup
        ResourceLock.release_all_locks(self.logger)

        mock_script.assert_any_call(keys=["lock-leaked-target"], args=[lid])
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    @patch("artemis.resource_lock.REDIS")
    def test_release_all_locks_is_thread_safe(self, mock_redis: MagicMock, mock_script: MagicMock) -> None:
        """release_all_locks must not corrupt state when called concurrently
        with lock acquire/release on other threads."""
        mock_redis.set.return_value = True
        errors = []

        def acquire_and_release() -> None:
            try:
                for i in range(20):
                    lock = ResourceLock(f"lock-thread-{threading.current_thread().name}-{i}", max_tries=1)
                    lock.acquire()
                    lock.release()
            except Exception as e:
                errors.append(e)

        def release_all_repeatedly() -> None:
            try:
                for _ in range(20):
                    ResourceLock.release_all_locks(self.logger)
            except Exception as e:
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

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    @patch("artemis.resource_lock.REDIS")
    def test_acquire_adds_to_sustain_dict(self, mock_redis: MagicMock) -> None:
        mock_redis.set.return_value = True

        lock = ResourceLock("lock-test-target", max_tries=1)
        lock.acquire()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertIn("lock-test-target", LOCKS_TO_SUSTAIN)

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    @patch("artemis.resource_lock.REDIS")
    def test_release_removes_from_sustain_dict_and_calls_script(self, mock_redis: MagicMock, mock_script: MagicMock) -> None:
        mock_redis.set.return_value = True

        lock = ResourceLock("lock-test-target", max_tries=1)
        lock.acquire()
        lid = lock.lid
        lock.release()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-test-target", LOCKS_TO_SUSTAIN)
        mock_script.assert_called_with(keys=["lock-test-target"], args=[lid])

    @patch("artemis.resource_lock.REDIS")
    def test_failed_acquire_raises(self, mock_redis: MagicMock) -> None:
        mock_redis.set.return_value = False  # NX fails — lock already held

        lock = ResourceLock("lock-contended", max_tries=1)

        with self.assertRaises(FailedToAcquireLockException):
            lock.acquire()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-contended", LOCKS_TO_SUSTAIN)

    @patch("artemis.resource_lock.RELEASE_LOCK_SCRIPT")
    @patch("artemis.resource_lock.REDIS")
    def test_context_manager_releases_on_exit(self, mock_redis: MagicMock, mock_script: MagicMock) -> None:
        mock_redis.set.return_value = True

        with ResourceLock("lock-ctx", max_tries=1) as _:
            with LOCKS_TO_SUSTAIN_LOCK:
                self.assertIn("lock-ctx", LOCKS_TO_SUSTAIN)
                lid = LOCKS_TO_SUSTAIN["lock-ctx"]

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-ctx", LOCKS_TO_SUSTAIN)
        mock_script.assert_called_with(keys=["lock-ctx"], args=[lid])


class TestIsAcquired(unittest.TestCase):
    """Verify is_acquired() semantics."""

    def setUp(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    @patch("artemis.resource_lock.REDIS")
    def test_is_acquired_true_when_any_holder(self, mock_redis: MagicMock) -> None:
        """is_acquired() returns True if the key exists, regardless of who holds it."""
        mock_redis.get.return_value = b"some-other-uuid"
        lock = ResourceLock("lock-target", max_tries=1)
        self.assertTrue(lock.is_acquired())

    @patch("artemis.resource_lock.REDIS")
    def test_is_acquired_false_when_free(self, mock_redis: MagicMock) -> None:
        mock_redis.get.return_value = None
        lock = ResourceLock("lock-target", max_tries=1)
        self.assertFalse(lock.is_acquired())



if __name__ == "__main__":
    unittest.main()
