import sys
import threading
import time
from logging import Logger
from random import uniform
from typing import Any, Dict, Optional
from uuid import uuid4

from redis import Redis

from artemis.config import Config


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


def sustain_locks() -> None:
    while True:
        with LOCKS_TO_SUSTAIN_LOCK:
            for key, value in LOCKS_TO_SUSTAIN.items():
                REDIS.set(key, value, ex=LOCK_HEARTBEAT_TIMEOUT)
        time.sleep(1)


LOCK_SUSTAIN_THREAD = threading.Thread(target=sustain_locks)
LOCK_SUSTAIN_THREAD.daemon = True
LOCK_SUSTAIN_THREAD.start()


class ResourceLock:
    def __init__(self, res_name: str, max_tries: Optional[int] = None):
        self.res_name = res_name
        self.lid = str(uuid4()) + "-" + " ".join(sys.argv)
        self.max_tries = max_tries

    @staticmethod
    def release_all_locks(logger: Logger) -> None:
        with LOCKS_TO_SUSTAIN_LOCK:
            for lock in LOCKS_TO_SUSTAIN:
                logger.info(f"Releasing lock: {lock} -> {LOCKS_TO_SUSTAIN[lock]}")

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
            if self.res_name in LOCKS_TO_SUSTAIN:
                del LOCKS_TO_SUSTAIN[self.res_name]
        REDIS.delete(self.res_name)

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()
