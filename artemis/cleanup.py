import datetime
import json
import time

from karton.core import Consumer
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig

from artemis import utils
from artemis.config import Config
from artemis.db import DB
from artemis.karton_utils import get_num_pending_tasks, is_analysis_finished

logger = utils.build_logger(__name__)

DONT_CLEANUP_TASKS_FRESHER_THAN__DAYS = 3
DELAY_BETWEEN_CLEANUPS__SECONDS = 4 * 3600
OLD_MODULES = ["dalfox", "http_service_to_url", "nuclei", "api_scanner"]

db = DB()


def _migrate_nuclei_queues() -> None:
    backend = KartonBackend(config=KartonConfig())

    for source_queue in backend.redis.scan_iter(match="karton.queue.*:nuclei"):
        destination_queue = source_queue[: -len(":nuclei")] + ":nuclei-router"

        moved_in_queue = 0
        while backend.redis.rpoplpush(source_queue, destination_queue):  # type: ignore
            moved_in_queue += 1

        if moved_in_queue > 0:
            logger.info(
                "Migrated %d task(s) from %s to %s",
                moved_in_queue,
                source_queue,
                destination_queue,
            )


def _cleanup_tasks_not_in_queues() -> None:
    # Until https://github.com/CERT-Polska/karton/issues/262 gets fixed, let's have our own cleanup routine
    backend = KartonBackend(config=KartonConfig())

    tasks = set()
    for key in backend.redis.scan_iter(match="karton.task*"):
        if ":" in key:
            tasks.add(key.split(":")[1])
        else:
            logger.error("Invalid key: %s", key)

    queued_tasks = set()
    for key in backend.redis.scan_iter(match="karton.queue*"):
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
            < datetime.datetime.utcnow() - datetime.timedelta(days=DONT_CLEANUP_TASKS_FRESHER_THAN__DAYS)
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


def _cleanup_module_started_tasks() -> None:
    removed_rows = db.delete_module_started_tasks_for_finished_analyses()
    if removed_rows:
        logger.info("Removed %d deduplication markers for finished analyses.", removed_rows)


def _update_analysis_finished_times() -> None:
    """Marks finished analyses with the time we first saw them finished, so they can be removed N days later."""
    num_pending_tasks = get_num_pending_tasks(KartonBackend(config=KartonConfig()))

    if not num_pending_tasks and Config.Miscellaneous.CLEANUP_RAISE_ERROR_ON_NON_UNFINISHED_ANALYSES:
        raise AssertionError("Did not found unfinished analyses during cleanup.")

    now = datetime.datetime.now()
    for analysis in db.list_analysis():
        if is_analysis_finished(analysis, num_pending_tasks):
            db.set_analysis_finished_time(analysis["id"], now)


def _cleanup_old_finished_analyses() -> None:
    max_age_days = Config.Miscellaneous.REMOVE_FINISHED_ANALYSES_AFTER_DAYS
    if max_age_days <= 0:
        return

    cutoff = datetime.datetime.now() - datetime.timedelta(days=max_age_days)

    analysis_ids_to_remove = [
        analysis["id"]
        for analysis in db.list_analysis()
        if analysis["finished_at"] is not None and analysis["finished_at"] < cutoff
    ]
    logger.info("Found %d analyses finished for more than %d days", len(analysis_ids_to_remove), max_age_days)

    # introducing batches to not overwhelm database
    BATCH = 100
    removed_analyses = 0
    for i in range(0, len(analysis_ids_to_remove), BATCH):
        analysis_ids = analysis_ids_to_remove[i : i + BATCH]
        removed_analyses += db.delete_analyses_by_ids(analysis_ids)

        # ModuleStartedTask rows are deduplication markers: "this module already dispatched this
        # task for this analysis". They're of no use once the analysis is gone, and nobody else
        # removes them (_cleanup_module_started_tasks() handles only the existing analyses).
        db.delete_module_started_tasks_for_analyses(analysis_ids)

    logger.info("Removed %d analyses finished for more than %d days", removed_analyses, max_age_days)


def cleanup() -> None:
    # this needs to be firstafter so that old Nuclei queue gets migrated before it gets removed
    _migrate_nuclei_queues()
    _cleanup_tasks_not_in_queues()
    _cleanup_queues()
    _update_analysis_finished_times()
    _cleanup_module_started_tasks()
    _cleanup_old_finished_analyses()


if __name__ == "__main__":
    while True:
        try:
            cleanup()
        except Exception:
            logger.exception("Error during cleanup")
        time.sleep(DELAY_BETWEEN_CLEANUPS__SECONDS)
