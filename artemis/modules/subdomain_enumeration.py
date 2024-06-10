#!/usr/bin/env python3
import urllib.parse
import re
import string
import time
from typing import Optional, Set
from bs4 import BeautifulSoup
import requests
from psycopg2 import OperationalError, connect

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error

DOMAIN_REGEX = r"([a-z0-9\-]+\.)+[a-z0-9\-]+"

class subdomain_enumeration(ArtemisBase):
    """
    Consumes `type: domain` to gather subdomains and produces `type: domain`.
    """

    identity = "subdomain_enumeration"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]
    lock_target = False
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
                    "amass",
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
            self.get_subdomains_from_subfinder(domain) |
            self.get_subdomains_from_amass(domain)
        )

        for subdomain in subdomains:
            if is_subdomain(subdomain, domain):
                task = Task(
                    {"type": TaskType.DOMAIN},
                    payload={"domain": subdomain},
                )
                self.add_task(current_task, task)

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(subdomains))
        self.log.info(f"Added {len(subdomains)} subdomains to scan")

if __name__ == "__main__":
    subdomain_enumeration().loop()