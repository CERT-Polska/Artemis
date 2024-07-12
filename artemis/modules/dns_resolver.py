#!/usr/bin/env python3
from typing import List, Set

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.resolvers import lookup


class DNSResolver(ArtemisBase):
    """
    Collects `type: DOMAIN`, performs DNS resolution, and produces `type: IP` tasks.
    """

    identity = "dns_resolver"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)
        resolved_ips: Set[str] = lookup(domain)

        if not resolved_ips:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Unable to resolve domain: {domain}",
            )
            return

        for ip in resolved_ips:
            new_task = Task(
                {"type": TaskType.IP},
                payload={TaskType.IP: ip},
                payload_persistent={"original_domain": domain},
            )
            self.add_task(current_task, new_task)

        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.OK,
            data=list(resolved_ips),
        )


if __name__ == "__main__":
    DNSResolver().loop()
