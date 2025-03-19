#!/usr/bin/env python3
from socket import gethostbyaddr
from typing import List

import requests
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase
from artemis.resolvers import lookup
from artemis.task_utils import get_ip_range, has_ip_range


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class ReverseDNSLookup(ArtemisBase):
    """
    Collects `type: IP`, performs reverse DNS lookup and produces `type: NEW` tasks.
    """

    identity = "ReverseDNSLookup"
    filters = [
        {"type": TaskType.IP.value},
    ]

    def _lookup(self, ip: str) -> List[str]:
        hosts = []
        # Download hostname data from external APIs
        for api in Config.Modules.ReverseDNSLookup.REVERSE_DNS_APIS:
            if not api:
                continue

            if not api.endswith("/"):
                api = api + "/"

            response = requests.get(api + ip)
            json_data = response.json()
            if "hostnames" in json_data:
                self.log.info(f"Got hosts {json_data['hostnames']} from {api}")
                hosts.extend(json_data["hostnames"])

        # Use the PTR record
        hostname, aliaslist, _ = gethostbyaddr(ip)
        if hostname not in aliaslist:
            aliaslist.append(hostname)
        hosts.extend(aliaslist)
        return list(set(hosts))

    def run(self, current_task: Task) -> None:
        ip = current_task.get_payload(TaskType.IP)
        found_domains = self._lookup(ip)
        actually_triggered_tasks = []

        for entry in found_domains:
            # We do not want to ask for reverse DNS if this IP was found during a domain scan. We don't want to
            # scan all other domains hosted on a server.
            if (
                has_ip_range(current_task)
                and "original_domain" not in current_task.payload_persistent
                and "last_domain" not in current_task.payload
            ):
                ip_range = get_ip_range(current_task)
                matches = [ip in ip_range for ip in lookup(entry)]
                if len(matches) and all(matches):
                    new_task = Task({"type": TaskType.NEW}, payload={"data": entry})
                    actually_triggered_tasks.append(entry)
                    self.add_task(current_task, new_task)

            if "original_domain" in current_task.payload_persistent:
                if not Config.Miscellaneous.VERIFY_REVDNS_IN_SCOPE or is_subdomain(
                    entry, current_task.payload_persistent["original_domain"]
                ):
                    new_task = Task({"type": TaskType.NEW}, payload={"data": entry})
                    actually_triggered_tasks.append(entry)
                    self.add_task(current_task, new_task)

        self.log.info(
            f"reverse DNS lookup found domains: {found_domains}, actually triggered tasks for {actually_triggered_tasks}"
        )
        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.OK,
            data={"found_domains": found_domains, "actually_triggered_tasks": actually_triggered_tasks},
        )


if __name__ == "__main__":
    ReverseDNSLookup().loop()
