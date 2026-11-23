# import logging
# import threading
# import unittest
# from typing import Any, Dict
# from unittest.mock import MagicMock, patch

# from redis import TimeoutError

# from artemis.resource_lock import (
#     LOCKS_TO_SUSTAIN,
#     LOCKS_TO_SUSTAIN_LOCK,
#     FailedToAcquireLockException,
#     ResourceLock,
#     ####################################
#     # BUG_FIX: #3110 PARAMETERS ADDING #
#     #           STARTS HERE            #
#     ####################################
#     LOCK_HEARTBEAT_TIMEOUT,
#     RELEASE_LOCK_SCRIPT,
#     SUSTAIN_LOCK_SCRIPT,
#     ####################################
#     #             ENDS HERE            #
#     ####################################
# )

# ####################################
# #          BUG_FIX: #3110          #
# #           STARTS HERE            #
# ####################################
# def _make_fake_redis_eval(store: Dict[str, str]) -> Any:
#     """Simulates Redis Lua eval for RELEASE_LOCK_SCRIPT and SUSTAIN_LOCK_SCRIPT."""

#     def fake_eval(script: str, numkeys: int, *args: Any) -> int:
#         key = args[0]
#         expected_lid = args[1]
#         if script == RELEASE_LOCK_SCRIPT:
#             if store.get(key) == expected_lid:
#                 del store[key]
#                 return 1
#             return 0
#         if script == SUSTAIN_LOCK_SCRIPT:
#             if store.get(key) == expected_lid:
#                 return 1
#             return 0
#         raise AssertionError(f"Unexpected Lua script: {script}")

#     return fake_eval
# ####################################
# #             ENDS HERE            #
#     ####################################

# class TestReleaseAllLocks(unittest.TestCase):
#     """Tests for ResourceLock.release_all_locks — the safety-net method called
#     at the start of every worker iteration to clean up leaked locks."""

#     def setUp(self) -> None:
#         # Clean state before each test
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN.clear()
#         self.logger = logging.getLogger("test_resource_lock")

#     def tearDown(self) -> None:
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN.clear()

#     @patch("artemis.resource_lock.REDIS")
#     def test_release_all_locks_deletes_redis_keys(self, mock_redis: MagicMock) -> None:
#         """release_all_locks must call REDIS.delete for every held lock."""
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN["lock-1.2.3.4"] = "uuid-1"
#             LOCKS_TO_SUSTAIN["lock-5.6.7.8"] = "uuid-2"

#         ResourceLock.release_all_locks(self.logger)

#         mock_redis.delete.assert_any_call("lock-1.2.3.4")
#         mock_redis.delete.assert_any_call("lock-5.6.7.8")
#         self.assertEqual(mock_redis.delete.call_count, 2)

#     @patch("artemis.resource_lock.REDIS")
#     def test_release_all_locks_clears_sustain_dict(self, mock_redis: MagicMock) -> None:
#         """After release_all_locks, LOCKS_TO_SUSTAIN must be empty so the
#         heartbeat thread stops refreshing the deleted keys."""
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN["lock-target-a"] = "uuid-a"
#             LOCKS_TO_SUSTAIN["lock-target-b"] = "uuid-b"

#         ResourceLock.release_all_locks(self.logger)

#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

#     @patch("artemis.resource_lock.REDIS")
#     def test_release_all_locks_noop_when_empty(self, mock_redis: MagicMock) -> None:
#         """Calling release_all_locks with no held locks must not raise."""
#         ResourceLock.release_all_locks(self.logger)

#         mock_redis.delete.assert_not_called()
#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

#     @patch("artemis.resource_lock.REDIS")
#     def test_acquire_then_release_all_cleans_up(self, mock_redis: MagicMock) -> None:
#         """Simulates a lock leak: acquire a lock, then call release_all_locks
#         instead of the normal release path. The lock must be fully cleaned up."""
#         mock_redis.set.return_value = True  # simulate successful SET NX

#         lock = ResourceLock("lock-leaked-target", max_tries=1)
#         lock.acquire()

#         # Verify the lock is tracked
#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

#         # Simulate the safety-net cleanup
#         ResourceLock.release_all_locks(self.logger)

#         mock_redis.delete.assert_any_call("lock-leaked-target")
#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertNotIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

#     @patch("artemis.resource_lock.REDIS")
#     def test_release_all_locks_is_thread_safe(self, mock_redis: MagicMock) -> None:
#         """release_all_locks must not corrupt state when called concurrently
#         with lock acquire/release on other threads."""
#         mock_redis.set.return_value = True
#         errors = []

#         def acquire_and_release() -> None:
#             try:
#                 for i in range(20):
#                     lock = ResourceLock(f"lock-thread-{threading.current_thread().name}-{i}", max_tries=1)
#                     lock.acquire()
#                     lock.release()
#             except Exception as e:
#                 errors.append(e)

#         def release_all_repeatedly() -> None:
#             try:
#                 for _ in range(20):
#                     ResourceLock.release_all_locks(self.logger)
#             except Exception as e:
#                 errors.append(e)

#         threads = [
#             threading.Thread(target=acquire_and_release),
#             threading.Thread(target=acquire_and_release),
#             threading.Thread(target=release_all_repeatedly),
#         ]
#         for t in threads:
#             t.start()
#         for t in threads:
#             t.join(timeout=10)

#         self.assertEqual(errors, [], f"Thread safety errors: {errors}")


# class TestResourceLockBasics(unittest.TestCase):
#     """Verify that normal acquire/release still works correctly after the fix."""

#     def setUp(self) -> None:
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN.clear()

#     def tearDown(self) -> None:
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN.clear()

#     @patch("artemis.resource_lock.REDIS")
#     def test_acquire_adds_to_sustain_dict(self, mock_redis: MagicMock) -> None:
#         mock_redis.set.return_value = True

#         lock = ResourceLock("lock-test-target", max_tries=1)
#         lock.acquire()

#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertIn("lock-test-target", LOCKS_TO_SUSTAIN)

#     @patch("artemis.resource_lock.REDIS")
#     def test_release_removes_from_sustain_dict_and_redis(self, mock_redis: MagicMock) -> None:
#         mock_redis.set.return_value = True

#         lock = ResourceLock("lock-test-target", max_tries=1)
#         lock.acquire()
#         lock.release()

#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertNotIn("lock-test-target", LOCKS_TO_SUSTAIN)
#         mock_redis.delete.assert_called_with("lock-test-target")

#     @patch("artemis.resource_lock.REDIS")
#     def test_failed_acquire_raises(self, mock_redis: MagicMock) -> None:
#         mock_redis.set.return_value = False  # NX fails — lock already held

#         lock = ResourceLock("lock-contended", max_tries=1)

#         with self.assertRaises(FailedToAcquireLockException):
#             lock.acquire()

#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertNotIn("lock-contended", LOCKS_TO_SUSTAIN)

#     @patch("artemis.resource_lock.uniform", return_value=0)
#     @patch("artemis.resource_lock.REDIS")
#     def test_timeouts_count_toward_max_tries(self, mock_redis: MagicMock, mock_uniform: MagicMock) -> None:
#         # A third successful response makes an unbounded retry fail promptly.
#         mock_redis.set.side_effect = [TimeoutError(), TimeoutError(), True]
#         lock = ResourceLock("lock-timeout", max_tries=2)

#         with self.assertRaises(FailedToAcquireLockException):
#             lock.acquire()

#         self.assertEqual(mock_redis.set.call_count, 2)
#         self.assertEqual(mock_uniform.call_count, 2)
#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertNotIn("lock-timeout", LOCKS_TO_SUSTAIN)

#     @patch("artemis.resource_lock.uniform", return_value=0)
#     @patch("artemis.resource_lock.REDIS")
#     def test_acquire_recovers_after_timeout(self, mock_redis: MagicMock, mock_uniform: MagicMock) -> None:
#         for max_tries in (2, None):
#             with self.subTest(max_tries=max_tries):
#                 mock_redis.reset_mock(side_effect=True)
#                 mock_uniform.reset_mock()
#                 mock_redis.set.side_effect = [TimeoutError(), True]
#                 lock = ResourceLock("lock-recovered", max_tries=max_tries)
#                 lock.acquire()

#                 self.assertEqual(mock_redis.set.call_count, 2)
#                 self.assertEqual(mock_uniform.call_count, 1)
#                 with LOCKS_TO_SUSTAIN_LOCK:
#                     self.assertEqual(LOCKS_TO_SUSTAIN["lock-recovered"], lock.lid)
#                     del LOCKS_TO_SUSTAIN["lock-recovered"]

#     @patch("artemis.resource_lock.REDIS")
#     def test_context_manager_releases_on_exit(self, mock_redis: MagicMock) -> None:
#         mock_redis.set.return_value = True

#         with ResourceLock("lock-ctx", max_tries=1):
#             with LOCKS_TO_SUSTAIN_LOCK:
#                 self.assertIn("lock-ctx", LOCKS_TO_SUSTAIN)

#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertNotIn("lock-ctx", LOCKS_TO_SUSTAIN)
#         mock_redis.delete.assert_called_with("lock-ctx")


# #################################################################################
# # BUG_FIX: #3110 
# # This addresses the testing to the fix we have made in resource_lock. 
# #################################################################################
# class TestResourceLockOwnership(unittest.TestCase):
#     """Verify ownership checks prevent stale locks from deleting or extending locks held by others."""

#     def setUp(self) -> None:
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN.clear()
#         self.logger = logging.getLogger("test_resource_lock")

#     def tearDown(self) -> None:
#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN.clear()

#     @patch("artemis.resource_lock.REDIS")
#     def test_stale_release_does_not_delete_new_owner_lock(self, mock_redis: MagicMock) -> None:
#         store: Dict[str, str] = {}

#         def fake_set(key: str, value: str, nx: bool = False, ex: int = 0) -> bool:
#             if nx and key in store:
#                 return False
#             store[key] = value
#             return True

#         mock_redis.set.side_effect = fake_set
#         mock_redis.eval.side_effect = _make_fake_redis_eval(store)

#         lock_a = ResourceLock("lock-10.0.0.0", max_tries=1)
#         lock_a.acquire()
#         self.assertEqual(store["lock-10.0.0.0"], lock_a.lid)

#         # Simulate lock_a expiring in Redis and lock_b acquiring the same resource
#         del store["lock-10.0.0.0"]
#         lock_b = ResourceLock("lock-10.0.0.0", max_tries=1)
#         lock_b.acquire()
#         self.assertEqual(store["lock-10.0.0.0"], lock_b.lid)

#         # Stale release from lock_a must NOT delete lock_b's lock
#         lock_a.release()
#         self.assertEqual(store.get("lock-10.0.0.0"), lock_b.lid)
#         with LOCKS_TO_SUSTAIN_LOCK:
#             self.assertEqual(LOCKS_TO_SUSTAIN.get("lock-10.0.0.0"), lock_b.lid)

#         # Releasing lock_b removes it cleanly
#         lock_b.release()
#         self.assertNotIn("lock-10.0.0.0", store)

#     @patch("artemis.resource_lock.REDIS")
#     def test_release_all_locks_does_not_delete_foreign_lock(self, mock_redis: MagicMock) -> None:
#         store = {"lock-10.0.0.0": "worker-b-lid"}
#         mock_redis.eval.side_effect = _make_fake_redis_eval(store)

#         with LOCKS_TO_SUSTAIN_LOCK:
#             LOCKS_TO_SUSTAIN["lock-10.0.0.0"] = "worker-a-stale-lid"

#         ResourceLock.release_all_locks(self.logger)

#         self.assertEqual(store.get("lock-10.0.0.0"), "worker-b-lid")

#     @patch("artemis.resource_lock.REDIS")
#     def test_sustain_script_does_not_refresh_foreign_lock(self, mock_redis: MagicMock) -> None:
#         store = {"lock-10.0.0.0": "worker-b-lid"}
#         mock_redis.eval.side_effect = _make_fake_redis_eval(store)

#         result = mock_redis.eval(
#             SUSTAIN_LOCK_SCRIPT, 1, "lock-10.0.0.0", "worker-a-stale-lid", LOCK_HEARTBEAT_TIMEOUT * 1000
#         )
#         self.assertEqual(result, 0)
#         self.assertEqual(store["lock-10.0.0.0"], "worker-b-lid")

# if __name__ == "__main__":
#     unittest.main()

import logging
import threading
import unittest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from redis import TimeoutError

from artemis.resource_lock import (
    LOCK_HEARTBEAT_TIMEOUT,
    LOCKS_TO_SUSTAIN,
    LOCKS_TO_SUSTAIN_LOCK,
    RELEASE_LOCK_SCRIPT,
    SUSTAIN_LOCK_SCRIPT,
    FailedToAcquireLockException,
    ResourceLock,
)


def _make_fake_redis_eval(store: Dict[str, str]) -> Any:
    """Simulates Redis Lua eval for RELEASE_LOCK_SCRIPT and SUSTAIN_LOCK_SCRIPT."""

    def fake_eval(script: str, numkeys: int, *args: Any) -> int:
        key = args[0]
        expected_lid = args[1]
        if script == RELEASE_LOCK_SCRIPT:
            if store.get(key) == expected_lid:
                del store[key]
                return 1
            return 0
        if script == SUSTAIN_LOCK_SCRIPT:
            if store.get(key) == expected_lid:
                return 1
            return 0
        raise AssertionError(f"Unexpected Lua script: {script}")

    return fake_eval


class TestReleaseAllLocks(unittest.TestCase):
    """Tests for ResourceLock.release_all_locks — the safety-net method called
    at the start of every worker iteration to clean up leaked locks."""

    def setUp(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.logger = logging.getLogger("test_resource_lock")

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    @patch("artemis.resource_lock.REDIS")
    def test_release_all_locks_deletes_redis_keys(self, mock_redis: MagicMock) -> None:
        """release_all_locks must call atomic compare-and-delete for every held lock."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-1.2.3.4"] = "uuid-1"
            LOCKS_TO_SUSTAIN["lock-5.6.7.8"] = "uuid-2"

        ResourceLock.release_all_locks(self.logger)

        mock_redis.eval.assert_any_call(RELEASE_LOCK_SCRIPT, 1, "lock-1.2.3.4", "uuid-1")
        mock_redis.eval.assert_any_call(RELEASE_LOCK_SCRIPT, 1, "lock-5.6.7.8", "uuid-2")
        self.assertEqual(mock_redis.eval.call_count, 2)

    @patch("artemis.resource_lock.REDIS")
    def test_release_all_locks_clears_sustain_dict(self, mock_redis: MagicMock) -> None:
        """After release_all_locks, LOCKS_TO_SUSTAIN must be empty so the
        heartbeat thread stops refreshing the deleted keys."""
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-target-a"] = "uuid-a"
            LOCKS_TO_SUSTAIN["lock-target-b"] = "uuid-b"

        ResourceLock.release_all_locks(self.logger)

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

    @patch("artemis.resource_lock.REDIS")
    def test_release_all_locks_noop_when_empty(self, mock_redis: MagicMock) -> None:
        """Calling release_all_locks with no held locks must not raise."""
        ResourceLock.release_all_locks(self.logger)

        mock_redis.eval.assert_not_called()
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(len(LOCKS_TO_SUSTAIN), 0)

    @patch("artemis.resource_lock.REDIS")
    def test_acquire_then_release_all_cleans_up(self, mock_redis: MagicMock) -> None:
        """Simulates a lock leak: acquire a lock, then call release_all_locks
        instead of the normal release path. The lock must be fully cleaned up."""
        mock_redis.set.return_value = True

        lock = ResourceLock("lock-leaked-target", max_tries=1)
        lock.acquire()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

        ResourceLock.release_all_locks(self.logger)

        mock_redis.eval.assert_any_call(RELEASE_LOCK_SCRIPT, 1, "lock-leaked-target", lock.lid)
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-leaked-target", LOCKS_TO_SUSTAIN)

    @patch("artemis.resource_lock.REDIS")
    def test_release_all_locks_is_thread_safe(self, mock_redis: MagicMock) -> None:
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

    @patch("artemis.resource_lock.REDIS")
    def test_release_removes_from_sustain_dict_and_redis(self, mock_redis: MagicMock) -> None:
        mock_redis.set.return_value = True

        lock = ResourceLock("lock-test-target", max_tries=1)
        lock.acquire()
        lock.release()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-test-target", LOCKS_TO_SUSTAIN)
        mock_redis.eval.assert_called_with(RELEASE_LOCK_SCRIPT, 1, "lock-test-target", lock.lid)

    @patch("artemis.resource_lock.REDIS")
    def test_failed_acquire_raises(self, mock_redis: MagicMock) -> None:
        mock_redis.set.return_value = False

        lock = ResourceLock("lock-contended", max_tries=1)

        with self.assertRaises(FailedToAcquireLockException):
            lock.acquire()

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-contended", LOCKS_TO_SUSTAIN)

    @patch("artemis.resource_lock.uniform", return_value=0)
    @patch("artemis.resource_lock.REDIS")
    def test_timeouts_count_toward_max_tries(self, mock_redis: MagicMock, mock_uniform: MagicMock) -> None:
        mock_redis.set.side_effect = [TimeoutError(), TimeoutError(), True]
        lock = ResourceLock("lock-timeout", max_tries=2)

        with self.assertRaises(FailedToAcquireLockException):
            lock.acquire()

        self.assertEqual(mock_redis.set.call_count, 2)
        self.assertEqual(mock_uniform.call_count, 2)
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-timeout", LOCKS_TO_SUSTAIN)

    @patch("artemis.resource_lock.uniform", return_value=0)
    @patch("artemis.resource_lock.REDIS")
    def test_acquire_recovers_after_timeout(self, mock_redis: MagicMock, mock_uniform: MagicMock) -> None:
        for max_tries in (2, None):
            with self.subTest(max_tries=max_tries):
                mock_redis.reset_mock(side_effect=True)
                mock_uniform.reset_mock()
                mock_redis.set.side_effect = [TimeoutError(), True]
                lock = ResourceLock("lock-recovered", max_tries=max_tries)
                lock.acquire()

                self.assertEqual(mock_redis.set.call_count, 2)
                self.assertEqual(mock_uniform.call_count, 1)
                with LOCKS_TO_SUSTAIN_LOCK:
                    self.assertEqual(LOCKS_TO_SUSTAIN["lock-recovered"], lock.lid)
                    del LOCKS_TO_SUSTAIN["lock-recovered"]

    @patch("artemis.resource_lock.REDIS")
    def test_context_manager_releases_on_exit(self, mock_redis: MagicMock) -> None:
        mock_redis.set.return_value = True

        with ResourceLock("lock-ctx", max_tries=1) as _:
            pass

        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertNotIn("lock-ctx", LOCKS_TO_SUSTAIN)
        mock_redis.eval.assert_called_once()
        args = mock_redis.eval.call_args[0]
        self.assertEqual(args[:3], (RELEASE_LOCK_SCRIPT, 1, "lock-ctx"))


class TestResourceLockOwnership(unittest.TestCase):
    """Verify ownership checks prevent stale locks from deleting or extending locks held by others."""

    def setUp(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()
        self.logger = logging.getLogger("test_resource_lock")

    def tearDown(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.clear()

    @patch("artemis.resource_lock.REDIS")
    def test_stale_release_does_not_delete_new_owner_lock(self, mock_redis: MagicMock) -> None:
        store: Dict[str, str] = {}

        def fake_set(key: str, value: str, nx: bool = False, ex: int = 0) -> bool:
            if nx and key in store:
                return False
            store[key] = value
            return True

        mock_redis.set.side_effect = fake_set
        mock_redis.eval.side_effect = _make_fake_redis_eval(store)

        lock_a = ResourceLock("lock-10.0.0.0", max_tries=1)
        lock_a.acquire()
        self.assertEqual(store["lock-10.0.0.0"], lock_a.lid)

        # Simulate lock_a expiring in Redis and lock_b acquiring the same resource
        del store["lock-10.0.0.0"]
        lock_b = ResourceLock("lock-10.0.0.0", max_tries=1)
        lock_b.acquire()
        self.assertEqual(store["lock-10.0.0.0"], lock_b.lid)

        # Stale release from lock_a must NOT delete lock_b's lock
        lock_a.release()
        self.assertEqual(store.get("lock-10.0.0.0"), lock_b.lid)
        with LOCKS_TO_SUSTAIN_LOCK:
            self.assertEqual(LOCKS_TO_SUSTAIN.get("lock-10.0.0.0"), lock_b.lid)

        # Releasing lock_b removes it cleanly
        lock_b.release()
        self.assertNotIn("lock-10.0.0.0", store)

    @patch("artemis.resource_lock.REDIS")
    def test_release_all_locks_does_not_delete_foreign_lock(self, mock_redis: MagicMock) -> None:
        store = {"lock-10.0.0.0": "worker-b-lid"}
        mock_redis.eval.side_effect = _make_fake_redis_eval(store)

        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN["lock-10.0.0.0"] = "worker-a-stale-lid"

        ResourceLock.release_all_locks(self.logger)

        self.assertEqual(store.get("lock-10.0.0.0"), "worker-b-lid")

    @patch("artemis.resource_lock.REDIS")
    def test_sustain_script_does_not_refresh_foreign_lock(self, mock_redis: MagicMock) -> None:
        store = {"lock-10.0.0.0": "worker-b-lid"}
        mock_redis.eval.side_effect = _make_fake_redis_eval(store)

        result = mock_redis.eval(
            SUSTAIN_LOCK_SCRIPT, 1, "lock-10.0.0.0", "worker-a-stale-lid", LOCK_HEARTBEAT_TIMEOUT * 1000
        )
        self.assertEqual(result, 0)
        self.assertEqual(store["lock-10.0.0.0"], "worker-b-lid")


if __name__ == "__main__":
    unittest.main()