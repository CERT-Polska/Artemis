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
from artemis.task_utils import (
    delete_analysis_finished_time,
    get_analysis_finished_time,
    set_analysis_finished_time,
)

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
    karton_backend = KartonBackend(config=KartonConfig())

    # First we take the set of all analyses, and then remove the ones that have any (also finished or
    # crashed) tasks. The result is the set of analyses that have no tasks in Karton at all. This is
    # deliberately more strict than is_analysis_finished(): crashed tasks can still be restarted, so
    # we keep the deduplication information as long as any task of the analysis exists.
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
            removed_rows += db.delete_module_started_tasks_for_analyses(analysis_ids)

            logger.debug("Cleaned up ModuleStartedTask table for analyses: %s", ",".join(analysis_ids))
        logger.info(
            "Removed %d rows in ModuleStartedTask table for %d finished analyses. "
            "Number of remaining unfinished analyses: %d.",
            removed_rows,
            len(finished_analyses_ids),
            kept_analyses,
        )


def _update_analysis_finished_times() -> None:
    """
    Mark each analysis with the time we first saw it finished, so that it can be removed
    N days after it finished. An analysis can already be finished without being declared as such -
    we observe the analyses only once per cleanup run. If Redis restarts and the finished timestamps
    get lost, analysis also behaves as "finished but not yet marked finished".
    """
    if Config.Miscellaneous.REMOVE_FINISHED_ANALYSES_AFTER_DAYS <= 0:
        return

    karton_backend = KartonBackend(config=KartonConfig())
    num_pending_tasks = get_num_pending_tasks(karton_backend)
    redis = karton_backend.redis

    # An unfinished analysis may still carry a mark - e.g. its crashed tasks were restarted after it
    # was marked - so stale marks are deleted here, before _cleanup_old_finished_analyses() sees them.
    for analysis in db.list_analysis():
        if not is_analysis_finished(analysis, num_pending_tasks):
            delete_analysis_finished_time(redis, analysis["id"])
        elif get_analysis_finished_time(redis, analysis["id"]) is None:
            set_analysis_finished_time(
                redis,
                analysis["id"],
                datetime.datetime.now(),
                ttl_seconds=Config.Miscellaneous.ANALYSIS_FINISHED_TIME_TTL_DAYS * 24 * 3600,
            )


def _cleanup_old_finished_analyses() -> None:
    max_age_days = Config.Miscellaneous.REMOVE_FINISHED_ANALYSES_AFTER_DAYS
    if max_age_days <= 0:
        return

    cutoff = datetime.datetime.now() - datetime.timedelta(days=max_age_days)
    redis = KartonBackend(config=KartonConfig()).redis

    analysis_ids_to_remove = [
        analysis["id"]
        for analysis in db.list_analysis()
        if (finished_at := get_analysis_finished_time(redis, analysis["id"])) is not None and finished_at < cutoff
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
        # removes them (_cleanup_module_started_tasks() iterates only over the existing analyses).
        db.delete_module_started_tasks_for_analyses(analysis_ids)

    logger.info("Removed %d analyses finished for more than %d days", removed_analyses, max_age_days)


def cleanup() -> None:
    # this needs to be firstafter so that old Nuclei queue gets migrated before it gets removed
    _migrate_nuclei_queues()
    _cleanup_tasks_not_in_queues()
    _cleanup_queues()
    _cleanup_module_started_tasks()
    _update_analysis_finished_times()
    _cleanup_old_finished_analyses()


if __name__ == "__main__":
    while True:
        try:
            cleanup()
        except Exception:
            logger.exception("Error during cleanup")
        time.sleep(DELAY_BETWEEN_CLEANUPS__SECONDS)
