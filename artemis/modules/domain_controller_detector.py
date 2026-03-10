#!/usr/bin/env python3
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host

# Ports associated with Active Directory / Domain Controller services that pose
# a risk when exposed to the internet. Each port is reported separately.
#
# Port list reference:
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts
#
# NOTE: SMB (445) is already handled by the port_scanner reporter (open_port_smb
# report type). RDP (3389) is handled as open_port_remote_desktop. We include them
# here only as a safety net in case fingerprintx classifies them as UNKNOWN service.
DC_PORTS = {
    88: "Kerberos",
    135: "RPC Endpoint Mapper",
    389: "LDAP",
    445: "SMB",
    464: "Kerberos Password Change",
    593: "RPC over HTTP",
    636: "LDAPS",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS",
    5722: "DFSR (Distributed File System Replication)",
    9389: "Active Directory Web Services",
}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class DomainControllerDetector(ArtemisBase):
    """
    Detects sensitive Active Directory / Domain Controller service ports
    exposed to the internet and reports each one individually.
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
            status_reason=f"{service_name} (port {port}) exposed on {host}",
        )


if __name__ == "__main__":
    DomainControllerDetector().loop()
