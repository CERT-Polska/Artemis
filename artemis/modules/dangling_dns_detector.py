import ipaddress
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.message
import dns.name
import dns.query
import dns.resolver
from dns import rdatatype
from dns.rdata import Rdata
from ipwhois import IPWhois  # type: ignore[import-not-found]
from ipwhois.exceptions import HTTPLookupError  # type: ignore[import-not-found]
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
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


def dns_query(target: str, record_type: rdatatype.RdataType) -> dns.resolver.Answer | None:
    try:
        resolver = dns.resolver.Resolver()
        return resolver.resolve(target, record_type)
    except Exception:
        return None


def ip_exists(ip: str, timeout: int = 5) -> bool:
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

    def check_port(port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            return False
        return False

    ports_to_check = [80, 443, 25, 110, 465, 587]
    with ThreadPoolExecutor(max_workers=len(ports_to_check)) as executor:
        if any(executor.map(check_port, ports_to_check)):
            return True
    return False


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

    def handle_retry_timeout(self, current_task: Task, task_type: TaskType) -> bool:
        """
        Handles all logic related to skipping the task if not available yet.

        :returns: True if Task is not available yet.
        """
        if task_type == TaskType.SUSPECTED_DANGLING_IP:
            available_at = current_task.payload.get("available_at")
            now = datetime.now(timezone.utc).timestamp()
            if available_at and now <= available_at:
                new_task = Task(
                    {
                        "type": TaskType.SUSPECTED_DANGLING_IP,
                    },
                    payload=current_task.payload,
                )

                # no need to keep data for deduplication
                # order is important, as we will not add new task before deleting previous scheduled_task
                if current_task.orig_uid:
                    self.db.delete_scheduled_task(current_task.orig_uid)
                self.add_task(current_task, new_task)

                self.log.info("Task is not available yet.")

                return True
        return False

    def handle_scheduling_retry(
        self, domain: str, current_task: Task, ip_records_alive: bool, last_ip_scan: bool
    ) -> bool:
        """
        Handles all logic related to scheduling retry task.

        :returns: True if Task was scheduled.
        """
        if not ip_records_alive and not last_ip_scan:
            retry_count = current_task.payload.get("retry_count", 0)

            new_payload = current_task.payload.copy()
            if retry_count == 0:
                # in order to not retry multiple subdomains that points towards the same ip
                # we remove domain from payload and add ip
                # last_domain is removed from deduplication logic, so we will store domain there
                ip = self.get_ip_from_domain(domain)
                new_payload["ip"] = ip
                if "domain" in new_payload:
                    new_payload["last_domain"] = new_payload["domain"]
                    del new_payload["domain"]

            new_payload["retry_count"] = retry_count + 1

            step = Config.Modules.DanglingDnsDetector.DANGLING_DNS_DELAY_STEP
            delay = min(step * (retry_count + 1), Config.Modules.DanglingDnsDetector.DANGLING_DNS_MAX_DELAY_RETRY)
            available_at = (datetime.now(timezone.utc) + timedelta(seconds=delay)).timestamp()
            new_payload["available_at"] = available_at

            new_task = Task(
                {
                    "type": TaskType.SUSPECTED_DANGLING_IP,
                },
                payload=new_payload,
            )

            self.log.info(
                "Rescheduling %s with delay=%ss, available_at=%s",
                domain,
                delay,
                available_at,
            )

            self.add_task(current_task, new_task)

            return True
        return False

    def _is_cname_dangling(self, record: Rdata, parent_domain: str) -> bool | None:
        if not hasattr(record, "rdtype") or record.rdtype != rdatatype.CNAME:
            return None

        cname_target_types = [rdatatype.A, rdatatype.AAAA, rdatatype.TXT]
        cname_target = record.target.to_text()  # type: ignore[attr-defined]

        if is_subdomain(cname_target, parent_domain):
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

    def check_dns_ip_records_are_alive(self, domain: str, result: list[dict[str, Any]], save_results: bool) -> bool:
        ip_records_alive = True
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
                            ip_records_alive = False
                        if dangling and save_results:
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
        return ip_records_alive

    def get_ip_from_domain(self, domain: str) -> str | None:
        try:
            answers = dns.resolver.resolve(domain, rdatatype.A, raise_on_no_answer=False)
            if answers.rrset is not None:
                for record in answers:
                    if hasattr(record, "rdtype") and record.rdtype == rdatatype.A:
                        return record.address  # type: ignore[attr-defined, no-any-return]

        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            return None

        return None

    def check_for_public_entities(self, domain: str) -> bool:
        # Dangling IP record detection can generate a high number of false positives when DNS IP records points to
        # unused server resources. The module used to determine that if IP is not responding it may be vulnberable to
        # takeover, but some entities, e.g. universities, are in control of the IP range that the domain resolved to
        # - thus leading to false positives.
        #
        # This method is a heuristic to filter out such entities based on results from RIPE.

        filters = ["university", "educational", "academic", "education", "institute of technology"]

        ip = self.get_ip_from_domain(domain)
        try:
            whois_data = IPWhois(ip).lookup_whois()
        except HTTPLookupError as e:
            if any(
                token in e
                for token in (
                    "429",
                    "too many requests",
                    "rate limit",
                    "quota",
                    "retry-after",
                    "503",
                )
            ):
                self.log.info("Quota exceeded for whois query for %s", ip)
                return False

        descriptions: list[str] = []
        if "asn_description" in whois_data and whois_data["asn_description"]:
            descriptions.append(whois_data["asn_description"])
        if "nets" in whois_data:
            for net in whois_data["nets"]:
                if "description" in net and net["description"]:
                    descriptions.append(net["description"])

        for descr in descriptions:
            if any(f.lower() in descr.lower() for f in filters):
                return True
        return False

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("last_domain")
        task_type = current_task.headers["type"]

        if self.handle_retry_timeout(current_task, task_type):
            # small delay in case of no active tasks to not spam que
            time.sleep(5)
            return

        retry_count = current_task.payload.get("retry_count", 0)
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

        last_ip_scan = retry_count >= Config.Modules.DanglingDnsDetector.DANGLING_DNS_NUMBER_OF_RETRIES_FOR_IP
        ip_records_alive = self.check_dns_ip_records_are_alive(domain, result, save_results=last_ip_scan)

        if task_type == TaskType.DOMAIN_THAT_MAY_NOT_EXIST:
            # we only check that once, no need to rerun that when suspecting dangling ip
            self.check_cname(domain, result)
            self.check_ns(domain, result)

        self.handle_scheduling_retry(domain, current_task, ip_records_alive, last_ip_scan)

        if last_ip_scan and not ip_records_alive and self.check_for_public_entities(domain):
            # clear result as we want to skip it
            result = []
            self.log.info("Domain %s IP determined as belonging to a public entity, not reporting dangling IP", domain)

        status = TaskStatus.INTERESTING if result else TaskStatus.OK
        messages = [r["message"] for r in result]
        status_reason = " ".join(messages) if messages else None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=result,
        )


if __name__ == "__main__":
    DanglingDnsDetector().loop()
