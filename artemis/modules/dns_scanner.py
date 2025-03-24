from typing import Any, Dict, Optional

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.resolver
import dns.xfr
import dns.zone
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_ip_range, has_ip_range

KNOWN_BAD_NAMESERVERS = ["fns1.42.pl", "fns2.42.pl"]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DnsScanner(ArtemisBase):
    """
    Check for domain transfer and known bad nameservers.
    """

    identity = "dns_scanner"
    filters = [{"type": TaskType.DOMAIN.value}]

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)

        findings = set()
        result: Dict[str, Any] = {}

        zone_name = dns.resolver.zone_for_name(domain)
        soa_result = [str(ns.mname) for ns in dns.resolver.resolve(zone_name, "SOA")]
        ns_result = [str(ns) for ns in dns.resolver.resolve(zone_name, "NS")]
        nameservers = list(set(soa_result + ns_result))

        # This will contain all nameservers, but we will skip checking for ones
        # that are outside of the scanned IP range.
        result["nameservers"] = nameservers

        result["nameservers_skipped_outside_ip_range"] = []

        for nameserver in nameservers:
            if nameserver in KNOWN_BAD_NAMESERVERS:
                findings.add(f"{nameserver} in known bad nameservers")

            nameserver_ip: Optional[str]
            try:
                nameserver_ip = str(dns.resolver.resolve(nameserver, "A")[0])
            except dns.resolver.NXDOMAIN:
                nameserver_ip = None
                result["ns_does_not_exist"] = True
                findings.add(f"{nameserver} domain does not exist - maybe it can be registered?")

            # If the task originated from scanning an IP range, that means, that we only want to
            # check the nameservers that belong to that IP range, not random ones.
            if nameserver_ip and has_ip_range(current_task) and nameserver_ip not in get_ip_range(current_task):
                result["nameservers_skipped_outside_ip_range"].append(nameserver_ip)
                continue

            nameserver_ok = False
            if nameserver_ip:
                try:
                    message: dns.message.Message = dns.query.udp(
                        dns.message.make_query(domain, "A"), nameserver_ip, timeout=1
                    )
                    if message.rcode() == dns.rcode.NXDOMAIN:
                        result["ns_not_knowing_domain"] = True
                    else:
                        nameserver_ok = True
                except dns.exception.Timeout:
                    pass

            if nameserver_ok:
                topmost_transferable_zone_name = None
                try:
                    zone_components = str(zone_name).rstrip(".").split(".")
                    for i in range(len(zone_components) - 1):
                        new_zone_name = ".".join(zone_components[i:])
                        if zone := dns.zone.from_xfr(dns.query.xfr(nameserver_ip, new_zone_name, timeout=1)):  # type: ignore[arg-type]
                            topmost_transferable_zone_name = new_zone_name
                            result["zone"] = zone.to_text()
                            result["zone_size"] = len(zone.nodes)
                except dns.xfr.TransferError:
                    pass

                if topmost_transferable_zone_name:
                    result["topmost_transferable_zone_name"] = topmost_transferable_zone_name
                    result["zone_transfer_nameserver"] = nameserver_ip
                    findings.add(
                        f"DNS zone transfer is possible (nameserver {nameserver_ip}, zone_name "
                        f"{result['topmost_transferable_zone_name']})"
                    )

        if len(findings) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found problems: " + ", ".join(sorted(findings))
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    DnsScanner().loop()
