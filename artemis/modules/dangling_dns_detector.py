import ipaddress
import socket
from typing import Any

import dns.message
import dns.name
import dns.query
import dns.resolver
from dns import rdatatype
from dns.rdata import Rdata
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host


def direct_dns_query(
    name: dns.name.Name, record_type: rdatatype.RdataType, server_ip: ipaddress.IPv4Address
) -> dns.message.Message | None:
    try:
        query = dns.message.make_query(name, record_type)
        response = dns.query.udp(query, str(server_ip), timeout=5)

        return response
    except Exception:
        return None


def edns_query(target: str, record_type: rdatatype.RdataType) -> dns.resolver.Answer | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_edns(True)
        return resolver.resolve(target, record_type)
    except Exception:
        return None


def ip_exists(ip: str, port: int = 80, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DanglingDnsDetector(ArtemisBase):
    """
    Check for dangling DNS records.
    """

    identity = "dangling_dns_detector"
    filters = [
        {"type": TaskType.DOMAIN_THAT_MAY_NOT_EXIST.value},
    ]

    def __check_cname(self, record: Rdata) -> bool | None:
        if not hasattr(record, "rdtype") or record.rdtype != rdatatype.CNAME:
            return None

        cname_target_types = [rdatatype.A, rdatatype.AAAA, rdatatype.TXT]
        cname_target = record.target.to_text()  # type: ignore[attr-defined]

        dangling = True
        for record_type in cname_target_types:
            response = edns_query(cname_target, record_type)

            if not response:
                continue

            for answer in response:
                if answer.rdtype == record_type:
                    dangling = False
                    break

        return dangling

    def check_cname(self, domain: str, result: list[dict[str, Any]]) -> None:
        try:
            answers = dns.resolver.resolve(domain, rdatatype.CNAME, raise_on_no_answer=False)
            if answers.rrset is not None:
                for record in answers:
                    dangling = self.__check_cname(record)
                    if dangling:
                        result.append(
                            {
                                "domain": domain,
                                "record": rdatatype.CNAME,
                                "message": (
                                    "The defined domain has CNAME record configured but the CNAME does not resolve."
                                ),
                            }
                        )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass

    def check_soa(
        self, domain: str, ns_name: dns.name.Name, server_ip: ipaddress.IPv4Address, result: list[dict[str, Any]]
    ) -> None:
        name = ns_name
        if not name.is_absolute():
            name = name.concatenate(dns.name.root)

        reply = direct_dns_query(name, rdatatype.SOA, server_ip)
        if not reply:
            result.append({"domain": domain, "record": rdatatype.NS, "message": "Target NS query failed."})
            return None

    def __check_ns(
        self,
        domain: str,
        qname: dns.name.Name,
        record: Rdata,
        result: list[dict[str, Any]],
    ) -> bool | None:
        if not hasattr(record, "rdtype") or record.rdtype != rdatatype.NS:
            return None

        ns_target = record.target.to_text()  # type: ignore[attr-defined]

        correct_responses = 0
        for record_type in [rdatatype.A, rdatatype.AAAA]:
            response = edns_query(ns_target, record_type)

            if not response:
                continue

            for answer in response:
                if record_type == rdatatype.A:
                    correct_responses += 1
                    self.check_soa(domain, qname, ipaddress.IPv4Address(answer.address), result)  # type: ignore[attr-defined]
                elif record_type == rdatatype.AAAA:
                    correct_responses += 1

        return correct_responses == 0

    def check_ns(self, domain: str, result: list[dict[str, Any]]) -> None:
        # It may generate false positives
        try:
            answers = dns.resolver.resolve(domain, rdatatype.NS, raise_on_no_answer=False)
            if answers.rrset is not None:
                for record in answers:
                    dangling = self.__check_ns(domain, answers.qname, record, result)
                    if dangling:
                        result.append(
                            {
                                "domain": domain,
                                "record": rdatatype.NS,
                                "message": "The defined domain has dangling NS record configured.",
                            }
                        )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass

    def check_dns_ip_records(self, domain: str, result: list[dict[str, Any]]) -> None:
        dns_ip_records = [rdatatype.A, rdatatype.AAAA]
        for dns_ip_record in dns_ip_records:
            try:
                answers = dns.resolver.resolve(domain, dns_ip_record, raise_on_no_answer=False)
                if answers.rrset is not None:
                    for record in answers:
                        if not hasattr(record, "rdtype") or record.rdtype != dns_ip_record:
                            continue

                        dangling = not ip_exists(record.address)  # type: ignore[attr-defined]
                        if dangling:
                            result.append(
                                {
                                    "domain": domain,
                                    "record": dns_ip_record,
                                    "message": f"The defined domain has {dns_ip_record.name} "
                                    f"record configured but the ip does not resolve.",
                                }
                            )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
                pass

    def run(self, current_task: Task) -> None:
        domain = get_target_host(current_task)

        result: list[dict[str, Any]] = []
        self.check_dns_ip_records(domain, result)
        self.check_cname(domain, result)
        self.check_ns(domain, result)

        status = TaskStatus.INTERESTING if result else TaskStatus.OK
        messages = [r["message"] for r in result]
        status_reason = " ".join(messages) if result else None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=result,
        )


if __name__ == "__main__":
    DanglingDnsDetector().loop()
