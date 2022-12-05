#!/usr/bin/env python3
from time import sleep
from typing import Dict, List

import shodan  # type: ignore
from karton.core import Task
from pydantic import BaseModel

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisSingleTaskBase

CRITICAL_VULN_NAMES = {
    "CVE-2020-10188": "cisco_os_telnetd",
    "CVE-2016-1421": "cisco_voip_rce",
    "CVE-2020-4448": "websphere_rce",
    "CVE-2020-12000": "ignition_rce",
    "CVE-2020-13249": "mariadb_rce",
    "CVE-2020-13379": "grafana_rce",
    "CVE-2019-13990": "oracle_fusion_rce",
    "CVE-2020-0796": "smbv3_smbghost_rce",
    "CVE-2020-2733": "oracle_jdedwards_rce",
    "CVE-2020-2884": "oracle_weblogic_rce",
    "CVE-2020-3240": "cisco_ucs_director_rce",
    "CVE-2020-3952": "vmware_vcenter_information_disclosure",
    "CVE-2020-5344": "dell_idrac_rce",
    "CVE-2020-7961": "liferay_rce",
    "CVE-2020-8515": "draytek_pre_auth_rce",
    "CVE-2020-8813": "cacti_rce",
    "CVE-2020-9294": "fortimail_0day",
    "CVE-2020-10109": "wistedweb_rce",
    "CVE-2020-10199": "nexus_repo_manager_rce",
    "CVE-2020-10374": "paessler_prtg_rce",
    "CVE-2020-10569": "sysaid_ajp_ghostcat_rce",
    "CVE-2020-11100": "haproxy_rce",
    "CVE-2020-11518": "zoho_manageengine_rce",
    "CVE-2020-11651": "saltstack_rce",
    "CVE-2020-12271": "sophos_xg_data_access",
    "CVE-2019-0708": "bluekeep_rdp_rce",
    "CVE-2019-10149": "exim_rce",
    "CVE-2019-11510": "pulse_vpn_rce",
    "CVE-2019-1652": "cisco_routers_rce",
    "CVE-2019-1653": "cisco_routers_rce",
    "CVE-2019-19781": "citrx_vpn_rce",
    "CVE-2020-0688": "exchange_rce",
    "CVE-2020-1938": "tomcat_ghostcat",
    "CVE-2021-27065": "exchange_rce",
    "MS17-010": "eternal_blue",
}


class ShodanVulnsResult(BaseModel):
    critical_vulns: Dict[str, str] = {}
    vulns: List[str] = []


class ShodanVulns(ArtemisSingleTaskBase):
    """
    Lists vulns from shodan
    """

    identity = "shodan_vulns"
    filters = [{"type": TaskType.IP}]

    def scan(self, current_task: Task, ip: str) -> None:
        result = ShodanVulnsResult()
        found_vuln_descriptions = []
        shodan_client = shodan.Shodan(Config.SHODAN_API_KEY)

        if vulns := shodan_client.host(ip).get("vulns"):
            result.vulns = vulns
            for vuln in vulns:
                if vuln in CRITICAL_VULN_NAMES:
                    result.critical_vulns[vuln] = CRITICAL_VULN_NAMES[vuln]
                    found_vuln_descriptions.append(f"{vuln}: {CRITICAL_VULN_NAMES[vuln]}")

        if len(found_vuln_descriptions) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found vulnerabilities from Shodan API: " + ", ".join(sorted(found_vuln_descriptions))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    def run(self, current_task: Task) -> None:
        ip = current_task.get_payload(TaskType.IP)
        with self.lock:
            sleep(1)
            self.scan(current_task, ip)


if __name__ == "__main__":
    if not Config.SHODAN_API_KEY:
        raise Exception("Shodan API key is required")

    ShodanVulns().loop()
