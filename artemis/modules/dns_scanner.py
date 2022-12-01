from typing import Dict, List, Optional, Union

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.resolver
import dns.xfr
import dns.zone
from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase

KNOWN_BAD_NAMESERVERS = ["fns1.42.pl", "fns2.42.pl"]


class DnsScanner(ArtemisBase):
    """
    Check for AXFR and known bad nameservers
    """

    identity = "dns_scanner"
    filters = [{"type": TaskType.DOMAIN}]

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)

        findings = []
        result: Dict[str, Union[bool, str, List[str]]] = {}

        zone_name = dns.resolver.zone_for_name(domain)
        soa_result = [str(ns.mname) for ns in dns.resolver.resolve(zone_name, "SOA")]
        ns_result = [str(ns) for ns in dns.resolver.resolve(zone_name, "NS")]
        nameservers = list(set(soa_result + ns_result))
        result["nameservers"] = nameservers

        for nameserver in nameservers:
            if nameserver in KNOWN_BAD_NAMESERVERS:
                findings.append(f"{nameserver} in known bad nameservers")

            nameserver_ip: Optional[str]
            try:
                nameserver_ip = str(dns.resolver.resolve(nameserver, "A")[0])
            except dns.resolver.NXDOMAIN:
                nameserver_ip = None
                result["ns_does_not_exist"] = True
                findings.append(f"{nameserver} domain does not exist, and therefore can be registered by a bad actor")

            nameserver_ok = False
            if nameserver_ip:
                try:
                    message: dns.message.Message = dns.query.udp(
                        dns.message.make_query(domain, "A"), nameserver_ip, timeout=1
                    )
                    if message.rcode() == dns.rcode.NXDOMAIN:  # type: ignore[attr-defined]
                        result["ns_not_knowing_domain"] = True
                        findings.append(f"the nameserver {nameserver_ip} ({nameserver}) doesn't know about the domain")
                    else:
                        nameserver_ok = True
                except dns.exception.Timeout:
                    result["ns_not_responding"] = True
                    findings.append(f"the nameserver {nameserver_ip} is not responding")

            if nameserver_ok:
                try:
                    if zone := dns.zone.from_xfr(dns.query.xfr(nameserver_ip, zone_name, timeout=1)):  # type: ignore[arg-type]
                        result["zone"] = zone.to_text()
                        findings.append("DNS zone transfer is possible")
                except dns.xfr.TransferError:
                    pass

        if len(findings) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found problems: " + ", ".join(sorted(findings))
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    DnsScanner().loop()
