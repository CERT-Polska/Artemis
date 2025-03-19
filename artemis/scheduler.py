from datetime import datetime
import pytz
from typing import Optional, List
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.base import JobLookupError
from karton.core.task import TaskPriority

from artemis.producer import create_tasks
from artemis import utils

logging.basicConfig(level=logging.INFO)

scheduler = BackgroundScheduler(timezone=pytz.utc)
scheduler.start()


def schedule_periodic_scan(targets: List[str], 
                           tag: Optional[str], 
                           disabled_modules: List[str], 
                           priority: int, 
                           interval_minutes: str, 
                           start_time: str, 
                           end_time: str) -> None:
    """
    Schedule a periodic scan job that runs at a fixed interval.

    :param targets: List[str] - targets to scan.
    :param tag: Optional[str] - a tag associated with the scan.
    :param disabled_modules: List[str] - modules to disable for the scan.
    :param priority: TaskPriority - priority of the scan tasks.
    :param interval_minutes: int - interval (in minutes) between each scan.
    :param start_time: datetime - when the first run should occur (UTC recommended).
    """
    def scan_job() -> None:
        # This function will be called every interval.
        logging.info("Running periodic scan for tag %s", tag)
        if end_time < datetime.utcnow():
            cancel_periodic_scan(job_id)
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
    logging.info("Scheduled periodic scan job '%d' to run every %d minutes starting at %s. ",
                job_id, interval_minutes, next_run_time)


def cancel_periodic_scan(job_id: int) -> None:
    """
    Cancel a previously scheduled periodic scan.
    """
    try:
        scheduler.remove_job(job_id)
        logging.info("Cancelled periodic scan job %s", job_id)
    except JobLookupError:
        logging.info("Job %s not found. It may have already been cancelled. ", job_id)
    

def get_scheduled_scans() -> List[int]:
    """
    Return a list of all currently scheduled periodic scans.

    Each item in the list is a dictionary with:
      - job_id: str
      - next_run_time: str (ISO format) or None
      - trigger: str representation of the APScheduler trigger
    """
    jobs_list = []
    for job in scheduler.get_jobs():
        jobs_list.append({
            "job_id": job.id,
            "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
            "trigger": str(job.trigger)
        })
    return jobs_list