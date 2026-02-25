import datetime
import json
import time

from karton.core import Consumer
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig

from artemis import utils
from artemis.config import Config
from artemis.db import DB

logger = utils.build_logger(__name__)

DONT_CLEANUP_TASKS_FRESHER_THAN__DAYS = 3
DELAY_BETWEEN_CLEANUPS__SECONDS = 4 * 3600
OLD_MODULES = ["dalfox"]

db = DB()


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


def _cleanup_scheduled_tasks() -> None:
    karton_backend = KartonBackend(config=KartonConfig())

    # First we take the set of all analyses, and then remove the ones that have tasks (i.e. unfinished). That way we result in the set of finished analyses.
    finished_analyses_ids_set = set()
    has_unfinished_analyses = False
    for analysis in db.list_analysis():
        finished_analyses_ids_set.add(analysis["id"])

    logger.info("Found %d analyses", len(finished_analyses_ids_set))

    kept_analyses = 0
    karton_existing_tasks = 0
    for task in karton_backend.iter_all_tasks():
        karton_existing_tasks += 1
        if task.root_uid in finished_analyses_ids_set:
            finished_analyses_ids_set.remove(task.root_uid)
            has_unfinished_analyses = True
            kept_analyses += 1

    if not has_unfinished_analyses and Config.Miscellaneous.CLEANUP_RAISE_ERROR_ON_NON_UNFINISHED_ANALYSES:
        raise AssertionError("Did not found unfinished analyses during cleanup.")

    logger.info("Iterated over %d karton tasks", karton_existing_tasks)
    finished_analyses_ids = list(finished_analyses_ids_set)
    if finished_analyses_ids:
        # introducing batches to not overwhelm database
        BATCH = 100
        removed_rows = 0
        for i in range(0, len(finished_analyses_ids), BATCH):
            analysis_ids = finished_analyses_ids[i : i + BATCH]
            rows = db.delete_scheduled_tasks_for_analyses(analysis_ids)
            removed_rows += rows

            logger.debug("Cleaned up ScheduledTask table for analyses: %s", ",".join(analysis_ids))
        logger.info(
            "Removed %d rows in ScheduleTask table for %d analyses; kept %d analyses.",
            removed_rows,
            len(finished_analyses_ids),
            kept_analyses,
        )


def cleanup() -> None:
    _cleanup_tasks_not_in_queues()
    _cleanup_queues()
    _cleanup_scheduled_tasks()


if __name__ == "__main__":
    while True:
        try:
            cleanup()
            time.sleep(DELAY_BETWEEN_CLEANUPS__SECONDS)
        except Exception:
            logger.exception("Error during cleanup")
