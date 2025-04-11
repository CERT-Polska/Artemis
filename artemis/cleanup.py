import datetime
import json
import time

from karton.core import Consumer
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig

from artemis import utils

logger = utils.build_logger(__name__)

DONT_CLEANUP_TASKS_FRESHER_THAN__DAYS = 3
DELAY_BETWEEN_CLEANUPS__SECONDS = 4 * 3600
OLD_MODULES = ["dalfox"]


def _cleanup_tasks_not_in_queues() -> None:
    # Until https://github.com/CERT-Polska/karton/issues/262 gets fixed, let's have our own cleanup routine
    backend = KartonBackend(config=KartonConfig())

    keys = backend.redis.keys()
    tasks = set()
    for key in keys:
        if key.startswith("karton.task"):
            if ":" in key:
                tasks.add(key.split(":")[1])
            else:
                logger.error("Invalid key: %s", key)

    queued_tasks = set()
    for key in keys:
        if key.startswith("karton.queue"):
            for task in backend.redis.lrange(key, 0, -1):
                queued_tasks.add(task)

    num_tasks_cleaned_up = 0
    for item in tasks - queued_tasks:
        key = "karton.task:" + item
        value = backend.redis.get(key)
        if not value:
            continue

        task = json.loads(value)
        if (
            datetime.datetime.utcfromtimestamp(task["last_update"])
            < datetime.datetime.now() - datetime.timedelta(days=DONT_CLEANUP_TASKS_FRESHER_THAN__DAYS)
            or task.get("headers", {}).get("receiver", "") in OLD_MODULES
        ):
            num_tasks_cleaned_up += 1
            backend.redis.delete(key)
    logger.info("Tasks cleaned up: %d", num_tasks_cleaned_up)


def _cleanup_queues() -> None:
    for old_module in OLD_MODULES:

        class KartonDummy(Consumer):
            identity = old_module

            def process(self, *args, **kwargs):  # type: ignore
                pass

        karton = KartonDummy(config=KartonConfig())
        karton.backend.unregister_bind(old_module)
        karton.backend.delete_consumer_queues(old_module)
        logger.info("Queue for %s is cleaned up", old_module)


def cleanup() -> None:
    _cleanup_tasks_not_in_queues()
    _cleanup_queues()


if __name__ == "__main__":
    while True:
        try:
            cleanup()
            time.sleep(DELAY_BETWEEN_CLEANUPS__SECONDS)
        except Exception:
            logger.exception("Error during cleanup")
