import logging
import os
import sys
import threading
import time
from logging import Logger
from random import uniform
from typing import Any, Dict, Optional
from uuid import uuid4

from redis import Redis

from artemis.config import Config

logger = logging.getLogger(__name__)


class FailedToAcquireLockException(Exception):
    """
    Used to indicate a lock that was not acquired in max_tries attempts.
    """


# This mechanism will sustain all acquired locks while the process is running. Therefore if it
# stops, the locks will expire.
LOCK_HEARTBEAT_TIMEOUT = 60
LOCKS_TO_SUSTAIN: Dict[str, str] = dict()

# This lock gatekeeps access to LOCKS_TO_SUSTAIN dict, as assuming dict access is thread-safe is a bad practice.
LOCKS_TO_SUSTAIN_LOCK = threading.Lock()

REDIS = Redis.from_url(Config.Data.REDIS_CONN_STR)

_RELEASE_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


def sustain_locks() -> None:
    while True:
        try:
            with LOCKS_TO_SUSTAIN_LOCK:
                for key, value in LOCKS_TO_SUSTAIN.items():
                    REDIS.set(key, value, ex=LOCK_HEARTBEAT_TIMEOUT)
        except Exception:
            logger.exception("Failed to sustain locks, will retry")
        time.sleep(1)


def _start_sustain_thread() -> None:
    t = threading.Thread(target=sustain_locks)
    t.daemon = True
    t.start()


_start_sustain_thread()


def _reinit_after_fork_in_child() -> None:
    # Only the calling thread survives fork(), so the sustain thread started at import
    # time is gone in the child. Reset the tracked-locks state (the parent still owns
    # those entries) and start a fresh heartbeat, otherwise acquired locks would silently
    # expire after LOCK_HEARTBEAT_TIMEOUT seconds.
    global LOCKS_TO_SUSTAIN, LOCKS_TO_SUSTAIN_LOCK
    LOCKS_TO_SUSTAIN = dict()
    LOCKS_TO_SUSTAIN_LOCK = threading.Lock()
    _start_sustain_thread()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reinit_after_fork_in_child)


def _release_lock_if_owned(res_name: str, lid: str) -> None:
    REDIS.eval(_RELEASE_SCRIPT, 1, res_name, lid)  # type: ignore[no-untyped-call]


class ResourceLock:
    def __init__(self, res_name: str, max_tries: Optional[int] = None):
        self.res_name = res_name
        self.lid = str(uuid4()) + "-" + " ".join(sys.argv)
        self.max_tries = max_tries

    @staticmethod
    def release_all_locks(logger: Logger) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            locks_to_release = list(LOCKS_TO_SUSTAIN.items())
            LOCKS_TO_SUSTAIN.clear()

        for lock, lid in locks_to_release:
            logger.info(f"Releasing lock: {lock} -> {lid}")
            _release_lock_if_owned(lock, lid)

    def acquire(self) -> None:
        """
        Acquires a lock.
        """
        attempts = 0
        while self.max_tries is None or attempts < self.max_tries:
            if REDIS.set(self.res_name, self.lid, nx=True, ex=LOCK_HEARTBEAT_TIMEOUT):
                with LOCKS_TO_SUSTAIN_LOCK:
                    LOCKS_TO_SUSTAIN[self.res_name] = self.lid
                return

            attempts += 1
            time.sleep(uniform(Config.Locking.LOCK_SLEEP_MIN_SECONDS, Config.Locking.LOCK_SLEEP_MAX_SECONDS))

        raise FailedToAcquireLockException()

    def is_acquired(self) -> bool:
        return REDIS.get(self.res_name) is not None

    def release(self) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            LOCKS_TO_SUSTAIN.pop(self.res_name, None)
        _release_lock_if_owned(self.res_name, self.lid)

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()
