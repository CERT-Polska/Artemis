#!/usr/bin/env python3
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskType
from artemis.module_base import ArtemisBase
from artemis.resolvers import lookup


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class IPLookup(ArtemisBase):
    """
    Collects `type: domain`, performs IP lookup and produces `type: NEW`.
    """

    identity = "IPLookup"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def _process(self, current_task: Task, domain: str) -> None:
        found_ips = lookup(domain)
        for found_ip in found_ips:
            new_task = Task({"type": TaskType.NEW}, payload={"data": found_ip})
            self.add_task(current_task, new_task)

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)
        self._process(current_task, domain)


if __name__ == "__main__":
    IPLookup().loop()
