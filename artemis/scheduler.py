from datetime import datetime
import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.base import JobLookupError

from artemis.producer import create_tasks
from artemis.task_utils import TaskPriority

scheduler = BackgroundScheduler(timezone=pytz.utc)
scheduler.start()


def schedule_periodic_scan(targets, tag, disabled_modules, priority, interval_minutes, start_time):
    """
    Schedule a periodic scan job that runs at a fixed interval.

    :param targets: List[str] - targets to scan.
    :param tag: Optional[str] - a tag associated with the scan.
    :param disabled_modules: List[str] - modules to disable for the scan.
    :param priority: TaskPriority - priority of the scan tasks.
    :param interval_minutes: int - interval (in minutes) between each scan.
    :param start_time: datetime - when the first run should occur (UTC recommended).
    """
    def scan_job():
        # This function will be called every interval.
        print(f"[{datetime.utcnow().isoformat()}] Running periodic scan for tag '{tag}'.")
        create_tasks(targets, tag, disabled_modules, priority)

    # Create a unique job id using the tag and a timestamp
    job_id = f"periodic_scan_{tag or 'untagged'}_{int(start_time.timestamp())}"

    # Ensure the next_run_time is in the future.
    next_run_time = start_time if start_time > datetime.utcnow() else datetime.utcnow()

    scheduler.add_job(
        scan_job,
        trigger="interval",
        minutes=interval_minutes,
        next_run_time=next_run_time,
        id=job_id,
        replace_existing=True,
    )
    print(f"Scheduled periodic scan job '{job_id}' to run every {interval_minutes} minutes starting at {next_run_time}.")


def cancel_periodic_scan(job_id):
    """
    Cancel a previously scheduled periodic scan.

    :param job_id: str - the id of the job to cancel.
    """
    try:
        scheduler.remove_job(job_id)
        print(f"Cancelled periodic scan job '{job_id}'.")
    except JobLookupError:
        print(f"Job '{job_id}' not found. It may have already been cancelled.")
