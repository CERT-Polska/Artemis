import ipaddress
import socket
import subprocess
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
from artemis.config import Config
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


def dns_query(target: str, record_type: rdatatype.RdataType) -> dns.resolver.Answer | None:
    try:
        resolver = dns.resolver.Resolver()
        return resolver.resolve(target, record_type)
    except Exception:
        return None


def ip_exists(ip: str, timeout: int = 5, num_retries: int = 20) -> bool:
    for _ in range(num_retries):
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        try:
            with socket.create_connection((ip, 80), timeout=timeout):
                return True
        except Exception:
            pass

        try:
            with socket.create_connection((ip, 443), timeout=timeout):
                return True
        except Exception:
            pass

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

    def _is_cname_dangling(self, record: Rdata) -> bool | None:
        if not hasattr(record, "rdtype") or record.rdtype != rdatatype.CNAME:
            return None

        cname_target_types = [rdatatype.A, rdatatype.AAAA, rdatatype.TXT]
        cname_target = record.target.to_text()  # type: ignore[attr-defined]

        dangling = True
        for record_type in cname_target_types:
            response = dns_query(cname_target, record_type)

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
                    dangling = self._is_cname_dangling(record)
                    if dangling:
                        result.append(
                            {
                                "domain": domain,
                                "record": rdatatype.CNAME,
                                "target": record.target.to_text(),  # type: ignore[attr-defined]
                                "message": (
                                    "The defined domain has a CNAME record configured but the CNAME "
                                    "does not resolve. If the subdomain that the CNAME record points to "
                                    "can be bought, then takeover is possible."
                                ),
                            }
                        )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            pass

    def query_soa_record_for_ns(
        self, domain: str, ns_name: dns.name.Name, server_ip: ipaddress.IPv4Address, result: list[dict[str, Any]]
    ) -> None:
        name = ns_name
        if not name.is_absolute():
            name = name.concatenate(dns.name.root)

        reply = direct_dns_query(name, rdatatype.SOA, server_ip)
        if not reply:
            result.append({"domain": domain, "record": rdatatype.NS, "message": "Target NS query failed."})
            return None

    def _is_ns_dangling(
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
            response = dns_query(ns_target, record_type)

            if not response:
                continue

            for answer in response:
                if record_type == rdatatype.A:
                    correct_responses += 1
                    self.query_soa_record_for_ns(domain, qname, ipaddress.IPv4Address(answer.address), result)  # type: ignore[attr-defined]
                elif record_type == rdatatype.AAAA:
                    correct_responses += 1

        return correct_responses == 0

    def check_ns(self, domain: str, result: list[dict[str, Any]]) -> None:
        # It may generate false positives
        try:
            answers = dns.resolver.resolve(domain, rdatatype.NS, raise_on_no_answer=False)
            if answers.rrset is not None:
                for record in answers:
                    dangling = self._is_ns_dangling(domain, answers.qname, record, result)
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

    def check_dns_ip_records_are_alive(self, domain: str, result: list[dict[str, Any]]) -> None:
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
                                    "target": record.address,  # type: ignore[attr-defined]
                                    "message": f"The defined domain has an {dns_ip_record.name} "
                                    "record configured but the IP does not resolve. "
                                    "If IP belongs to a hosting provider and can be bought by other customer, "
                                    "then subdomain takeover is possible.",
                                }
                            )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
                pass

    def run(self, current_task: Task) -> None:
        domain = get_target_host(current_task)
        analysis = self.db.get_analysis_by_id(current_task.root_uid)
        root_domain = analysis.get("target") if analysis else None

        if Config.Modules.DanglingDnsDetector.DANGLING_DNS_SKIP_ROOT_DOMAIN and domain == root_domain:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason="Skipped: root domain",
            )
            return

        result: list[dict[str, Any]] = []
        self.check_dns_ip_records_are_alive(domain, result)
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
