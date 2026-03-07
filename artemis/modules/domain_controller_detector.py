#!/usr/bin/env python3
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host

# Ports that indicate a domain controller is likely exposed.
# Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts
DC_PORTS = {
    88: "Kerberos",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS",
}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class DomainControllerDetector(ArtemisBase):
    """
    Detects domain controller services exposed to the internet.
    """

    identity = "domain_controller_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        if port not in DC_PORTS:
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, status_reason=None)
            return

        service_name = DC_PORTS[port]
        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.INTERESTING,
            status_reason=f"{service_name} (port {port}) exposed on {host} — likely a domain controller",
        )


if __name__ == "__main__":
    DomainControllerDetector().loop()
