import ipaddress
import time
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
from artemis.domains import get_main_domain, is_subdomain
from artemis.module_base import ArtemisBase


def direct_dns_query(
    name: dns.name.Name, record_type: rdatatype.RdataType, server_ip: ipaddress.IPv4Address
) -> dns.message.Message | None:
    try:
        query = dns.message.make_query(name, record_type)
        response = dns.query.udp(query, str(server_ip), timeout=5)

        return response
    except Exception:
        return None


def dns_query(
    target: str, record_type: rdatatype.RdataType, retries: int = 3, delay: float = 1.0
) -> dns.resolver.Answer | None:
    resolver = dns.resolver.Resolver()
    for _ in range(retries):
        try:
            return resolver.resolve(target, record_type)
        except Exception:
            time.sleep(delay)
    return None


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DanglingDnsDetector(ArtemisBase):
    """
    Check for dangling DNS records.
    """

    identity = "dangling_dns_detector"
    filters = [
        {"type": TaskType.DOMAIN_THAT_MAY_NOT_EXIST.value},
        {"type": TaskType.SUSPECTED_DANGLING_IP.value},
    ]

    def _is_saas_namespace(self, ns_records: list[str]) -> bool:
        # Detect SAAS providers with multi-tenant DNS namespaces to avoid false positives
        # We want to still report record like e.g: username.github.io
        SAAS_NS_PATTERNS = [
            "azure-dns",
            "awsdns",
            "herokudns",
            "github",
            "cloudflare",
            "vercel",
            "netlify",
            "fastly",
        ]

        for ns in ns_records:
            for pattern in SAAS_NS_PATTERNS:
                if pattern in ns.lower():
                    return True
        return False

    def _is_cname_dangling(self, record: Rdata, parent_domain: str) -> bool | None:
        if not hasattr(record, "rdtype") or record.rdtype != rdatatype.CNAME:
            return None

        cname_target_types = [rdatatype.A, rdatatype.AAAA, rdatatype.TXT]
        cname_target = record.target.to_text()  # type: ignore[attr-defined]
        cname_target_zone = get_main_domain(cname_target)

        if cname_target_zone in Config.Modules.DanglingDnsDetector.DANGLING_DNS_KNOWN_DNS_ZONE_RECORDS_TO_SKIP:
            # we want to ensure to not reports popular cname targets like e.g: sipdir.online.lync.com
            return False

        if is_subdomain(cname_target, parent_domain):
            return False
        if is_subdomain(parent_domain, cname_target):
            return False

        dangling = True
        for record_type in cname_target_types:
            response = dns_query(cname_target, record_type)

            if not response:
                continue

            for answer in response:
                if answer.rdtype == record_type:
                    dangling = False
                    break

        if dangling and cname_target_zone:
            # If the zone has valid NS records and is not SaaS-managed,
            # treat it as misconfiguration instead of marking as dangling.
            # Purpose is to reduce number of FP.
            response = dns_query(cname_target_zone, rdatatype.NS)
            ns_records = [r.to_text() for r in response] if response else None
            if ns_records and not self._is_saas_namespace(ns_records):
                dangling = False

        return dangling

    def check_cname(self, domain: str, result: list[dict[str, Any]]) -> None:
        try:
            answers = dns.resolver.resolve(domain, rdatatype.CNAME, raise_on_no_answer=False)
            if answers.rrset is not None:
                for record in answers:
                    dangling = self._is_cname_dangling(record, parent_domain=domain)
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

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("last_domain")
        task_type = current_task.headers["type"]

        analysis = self.db.get_analysis_by_id(current_task.root_uid)
        root_domain = analysis.get("target") if analysis else None

        if Config.Modules.DanglingDnsDetector.DANGLING_DNS_SKIP_ROOT_DOMAIN and domain == root_domain:
            self.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason="Skipped: root domain",
            )
            return

        result: list[dict[str, Any]] = []

        if task_type == TaskType.DOMAIN_THAT_MAY_NOT_EXIST:
            # left for migration period
            self.check_cname(domain, result)
            self.check_ns(domain, result)

        status = TaskStatus.INTERESTING if result else TaskStatus.OK
        messages = [r["message"] for r in result]
        status_reason = " ".join(messages) if messages else None

        self.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=result,
        )


if __name__ == "__main__":
    DanglingDnsDetector.parallel_loop()
