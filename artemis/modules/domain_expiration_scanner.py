#!/usr/bin/env python3
import datetime
from typing import Any, Dict, Optional

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_main_domain
from artemis.module_base import ArtemisBase
from artemis.utils import perform_whois_or_sleep


class DomainExpirationScanner(ArtemisBase):
    """
    Alerts if domain expiration date is coming.
    """

    identity = "domain_expiration_scanner"
    filters = [{"type": TaskType.DOMAIN.value}]
    resource_name_to_lock_before_scanning = "whois"
    lock_target = False

    # As the logic sometimes requires waiting 24 hours for the quota to be renewed, let's
    # set the timeout for 24 hours + 1 hour.
    timeout_seconds = (24 + 1) * 3600

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)
        result: Dict[str, Any] = {}
        status = TaskStatus.OK
        status_reason = None
        if is_main_domain(domain):
            domain_data = perform_whois_or_sleep(domain=domain, logger=self.log)

            if domain_data:
                expiry_date = domain_data.expiration_date
                result = self._prepare_expiration_data(expiration_date=expiry_date, result=result)

                if "close_expiration_date" in result:
                    status = TaskStatus.INTERESTING
                    status_reason = self._prepare_expiration_status_reason(
                        days_to_expire=result["days_to_expire"], expiration_date=result["expiration_date"]
                    )

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    @staticmethod
    def _prepare_expiration_data(
        expiration_date: Optional[datetime.datetime], result: Dict[str, Any]
    ) -> Dict[str, Any]:
        days_to_expire = None
        now = datetime.datetime.now()
        if expiration_date:
            days_to_expire = (expiration_date - now).days
        result["expiration_date"] = expiration_date
        if days_to_expire and days_to_expire <= Config.Modules.DomainExpirationScanner.DOMAIN_EXPIRATION_TIMEFRAME_DAYS:
            result["close_expiration_date"] = True
            result["days_to_expire"] = days_to_expire
        return result

    @staticmethod
    def _prepare_expiration_status_reason(days_to_expire: int, expiration_date: datetime.datetime) -> str:
        return (
            f"Scanned domain will expire in {days_to_expire} days - on {expiration_date}."
            if days_to_expire != 1
            else f"Scanned domain will expire in {days_to_expire} day - on {expiration_date}."
        )


if __name__ == "__main__":
    DomainExpirationScanner().loop()
