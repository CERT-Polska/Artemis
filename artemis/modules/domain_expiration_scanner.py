#!/usr/bin/env python3
import datetime
import time
from typing import Any, Dict

from karton.core import Task
from whois import Domain, WhoisQuotaExceeded, query  # type: ignore

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_main_domain
from artemis.module_base import ArtemisBase


class DomainExpirationScanner(ArtemisBase):
    """
    Alerts if domain expiration date is coming.
    """

    identity = "domain_expiration_scanner"
    filters = [{"type": TaskType.DOMAIN.value}]

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)
        result: Dict[str, Any] = {}
        status = TaskStatus.OK
        status_reason = None
        if is_main_domain(domain):
            try:
                domain_data = self._query_whois(domain=domain)
            except WhoisQuotaExceeded:
                time.sleep(24 * 60 * 60)
                domain_data = self._query_whois(domain=domain)

            expiry_date = domain_data.expiration_date
            result = self._prepare_expiration_data(expiration_date=expiry_date, result=result)

            if "close_expiration_date" in result:
                status = TaskStatus.INTERESTING
                status_reason = self._prepare_expiration_status_reason(
                    days_to_expire=result["days_to_expire"], expiration_date=result["expiration_date"]
                )

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    @staticmethod
    def _query_whois(domain: str) -> Domain:
        return query(domain)

    @staticmethod
    def _prepare_expiration_data(expiration_date: datetime.datetime, result: Dict[str, Any]) -> Dict[str, Any]:
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
            f"Scanned domain will expire in {days_to_expire} days - (on {expiration_date})."
            if days_to_expire != 1
            else f"Scanned domain will expire in {days_to_expire} day - (on {expiration_date})."
        )


if __name__ == "__main__":
    DomainExpirationScanner().loop()
