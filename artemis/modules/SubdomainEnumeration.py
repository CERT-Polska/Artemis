#!/usr/bin/env python3
import time
from typing import Optional, Set

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error

DOMAIN_REGEX = r"([a-z0-9\-]+\.)+[a-z0-9\-]+"

# NOTE: The rappidns, jldc, gau and crtsh modules were removed from this class 
# as their functionality is already implemented internally by the subfinder and amass utilities.


class SubdomainEnumeration(ArtemisBase):
    """
    Consumes `type: domain` to gather subdomains and produces `type: domain`.
    """

    identity = "SubdomainEnumeration"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]
    lock_target = False

    def get_subdomains_with_retry(self, func, domain: str, retries: int = 20) -> Set[str]:
        for retry in range(retries):
            try:
                return func(domain)
            except Exception:
                self.log.exception("Retry %d/%d for %s", retry + 1, retries, func.__name__)
        return set()

    def get_subdomains_from_subfinder(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            result = check_output_log_on_error(
                [
                    "subfinder", 
                    "-d", 
                    domain, 
                    "-silent",
                    "-all",
                    "-recursive"
                    ],
                    self.log
            )
            subdomains.update(result.decode().splitlines())
        except Exception:
            self.log.exception("Unable to obtain information from subfinder for domain %s", domain)
        return subdomains

    def get_subdomains_from_amass(self, domain: str) -> Set[str]:
        subdomains: Set[str] = set()
        try:
            result = check_output_log_on_error(
                [
                    "amass", #amass is recursive by default use -norecursive to make it non-recursive
                    "enum",
                    "-d",
                    domain,
                    "-silent"
                ],
                self.log
            )
            subdomains.update(result.decode().splitlines())
        except Exception as e:
            if "panic: runtime error: invalid memory address or nil pointer dereference" in str(e):
                self.log.error(f"Amass encountered a runtime error for domain {domain}. Skipping subdomain enumeration.")
            else:
                self.log.exception("Unable to obtain information from amass for domain %s", domain)
        return subdomains


    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")
        subdomains = (
            self.get_subdomains_with_retry(self.get_subdomains_from_subfinder, domain) |
            self.get_subdomains_with_retry(self.get_subdomains_from_amass, domain)
        )

        if self.redis.get(f"SubdomainEnumeration-done-{domain}"):
            self.log.info(
                "SubdomainEnumeration has already returned %s - and as it's a recursive query, no further query will be performed.",
                domain,
            )
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(subdomains))
        self.log.info(f"Added {len(subdomains)} subdomains to scan")

if __name__ == "__main__":
    SubdomainEnumeration().loop()