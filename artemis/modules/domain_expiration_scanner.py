#!/usr/bin/env python3
import datetime
from typing import Any, Dict

from karton.core import Task
from whois import query  # type: ignore

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase


class DomainExpirationScanner(ArtemisBase):
    """
    Alerts if domain expiration date is coming.
    """

    identity = "domain_expiration_scanner"
    filters = [{"type": TaskType.DOMAIN.value}]

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)
        now = datetime.datetime.now()
        result: Dict[str, Any] = {}
        domain_data = query(domain)
        expiry_date = domain_data.expiration_date
        days_to_expire = None
        if expiry_date:
            days_to_expire = (expiry_date - now).days
        result["expiry_date"] = expiry_date
        if days_to_expire and days_to_expire <= Config.Modules.DomainExpirationScanner.DOMAIN_EXPIRATION_ALERT_IN_DAYS:
            result["close_expiry_date"] = True
            result["days_to_expire"] = days_to_expire
            status = TaskStatus.INTERESTING
            status_reason = (
                f"Scanned domain will expire in {days_to_expire} days."
                if days_to_expire != 1
                else f"Scanned domain will expire in {days_to_expire} day."
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    DomainExpirationScanner().loop()
