import time

from karton.core.task import TaskPriority

from artemis import utils
from artemis.db import DB
from artemis.producer import create_tasks

logger = utils.build_logger(__name__)

SCHEDULER_CHECK_INTERVAL_SECONDS = 60

db = DB()


def run_due_periodic_scans() -> None:
    due_scans = db.get_due_periodic_scans()
    logger.info("Found %d due periodic scan(s)", len(due_scans))

    for scan in due_scans:
        scan_id = scan["id"]
        targets = [t.strip() for t in scan["targets"].split("\n") if t.strip()]
        tag = scan.get("tag")
        disabled_modules_str = scan.get("disabled_modules", "")
        disabled_modules = [m for m in disabled_modules_str.split(",") if m] if disabled_modules_str else []
        priority = TaskPriority(scan.get("priority", "normal"))

        logger.info(
            "Running periodic scan %d: %d target(s), tag=%s, interval=%dh",
            scan_id,
            len(targets),
            tag,
            scan["interval_hours"],
        )

        try:
            task_ids = create_tasks(
                targets,
                tag,
                disabled_modules=disabled_modules,
                priority=priority,
            )
            logger.info("Periodic scan %d: created %d task(s): %s", scan_id, len(task_ids), task_ids)
        except Exception:
            logger.exception("Error running periodic scan %d", scan_id)

        db.mark_periodic_scan_as_run(scan_id)


if __name__ == "__main__":
    logger.info("Periodic scan scheduler started (check interval: %ds)", SCHEDULER_CHECK_INTERVAL_SECONDS)
    while True:
        try:
            run_due_periodic_scans()
        except Exception:
            logger.exception("Error in periodic scan scheduler loop")
        time.sleep(SCHEDULER_CHECK_INTERVAL_SECONDS)
