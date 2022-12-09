#!/usr/bin/env python3
from socket import gethostbyaddr
from typing import List

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase


class ReverseDNSLookup(ArtemisBase):
    """
    Collects `type: IP`, performs reverse DNS lookup and produces `type: NEW`
    """

    identity = "ReverseDNSLookup"
    filters = [
        {"type": TaskType.IP},
    ]

    @staticmethod
    def _lookup(ip: str) -> List[str]:
        # TODO: implement smarter mechanism and cache
        hostname, aliaslist, _ = gethostbyaddr(ip)
        if hostname not in aliaslist:
            aliaslist.append(hostname)
        return aliaslist

    def run(self, current_task: Task) -> None:
        if Config.CHECK_DOMAIN_IN_REVERSE_IP_LOOKUP and "original_domain" not in current_task.payload_persistent:
            # We will want to ensure the RevDNS result is a subdomain of the original
            # one so that we don't scan outside of the given domain.
            return

        ip = current_task.get_payload(TaskType.IP)
        found_domains = self._lookup(ip)
        for entry in found_domains:
            if (
                is_subdomain(entry, current_task.payload_persistent["original_domain"])
                or not Config.CHECK_DOMAIN_IN_REVERSE_IP_LOOKUP
            ):
                new_task = Task({"type": TaskType.NEW}, payload={"data": entry})
                self.add_task(current_task, new_task)

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=found_domains)


if __name__ == "__main__":
    ReverseDNSLookup().loop()
