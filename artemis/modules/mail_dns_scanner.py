#!/usr/bin/env python3
import dataclasses
import os
import socket
from smtplib import SMTP, SMTPServerDisconnected
from typing import List, Optional

import dns.name
import dns.resolver
from karton.core import Task
from publicsuffixlist import PublicSuffixList

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_main_domain
from artemis.mail_check.scan import DomainScanResult as SPFDMARCScanResult
from artemis.mail_check.scan import ScanningException, scan_domain
from artemis.module_base import ArtemisBase
from artemis.resolvers import ip_lookup
from artemis.utils import throttle_request

PUBLIC_SUFFIX_LIST = PublicSuffixList()


@dataclasses.dataclass
class MailDNSScannerResult:
    mail_server_found: bool = False
    spf_dmarc_scan_result: Optional[SPFDMARCScanResult] = None


class MailDNSScanner(ArtemisBase):
    """
    Checks whether there is a mail server associated with the current domain and checks if SPF and DMARC records are present.
    """

    identity = "mail_dns_scanner"
    filters = [{"type": TaskType.DOMAIN.value}]

    @staticmethod
    def is_smtp_server(host: str, port: int) -> bool:
        def test() -> bool:
            smtp = SMTP(timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS)
            try:
                smtp.connect(host, port=port)
                smtp.close()
                return True
            except socket.timeout:
                return False
            except ConnectionRefusedError:
                return False
            except OSError:
                return False
            except SMTPServerDisconnected:
                return False

        return throttle_request(test)  # type: ignore

    def scan(self, current_task: Task, domain: str) -> MailDNSScannerResult:
        result = MailDNSScannerResult()

        has_mx_records = False

        # Try to find an SMTP for current domain
        try:
            domain_mx_records = dns.resolver.resolve(domain, "MX")
            for domain_mx_record in domain_mx_records:
                exchange = str(domain_mx_record.exchange).removesuffix(".")
                result.mail_server_found = True
                has_mx_records = True
                for port in (25, 465, 587):
                    if self.is_smtp_server(exchange, port):
                        for host in [exchange] + list(ip_lookup(exchange)):
                            new_task = Task(
                                {
                                    "type": TaskType.SERVICE,
                                    "service": Service.SMTP,
                                },
                                payload={
                                    "host": host,
                                    "port": port,
                                    "mail_domain": domain,
                                },
                            )
                            self.add_task(current_task, new_task)
        except dns.resolver.NoAnswer:
            if self.is_smtp_server(domain, 25):
                result.mail_server_found = True

        try:
            # Ignore_void_dns_lookups is set because:
            # - the checkdmarc check is buggy and sometimes counts the void DNS lookups wrongly,
            # - sometimes the DNS lookups are void because of timeouts which can happen if there is
            #   a lot of scanning going on.
            result.spf_dmarc_scan_result = scan_domain(
                envelope_domain=domain,
                from_domain=domain,
                dkim_domain=None,
                parked=not has_mx_records,
                ignore_void_dns_lookups=True,
            )
        except ScanningException:
            self.log.exception("Unable to check domain %s", domain)

        # For Artemis we have a slightly relaxed requirement than mail_check - if a domain is not used for
        # sending e-mail, we don't require SPF (but require DMARC). Mail_check can't be modified as it's
        # used by CERT internal tools as well.
        #
        # We won't report lack of SPF record, but we should report if it's invalid.
        if (
            result.spf_dmarc_scan_result
            and result.spf_dmarc_scan_result.spf
            and result.spf_dmarc_scan_result.spf.record_not_found
            and not has_mx_records
        ):
            result.spf_dmarc_scan_result.spf.valid = True

        # To decrease the number of false positives, for domains that do have MX records, we require SPF records to
        # be present only if the domain is directly below a public suffix (so we will require SPF on example.com
        # but not on www.example.com).
        if (
            has_mx_records
            and PUBLIC_SUFFIX_LIST.privatesuffix(domain)
            and not PUBLIC_SUFFIX_LIST.privatesuffix(domain) == domain
            and result.spf_dmarc_scan_result
            and result.spf_dmarc_scan_result.spf
            and result.spf_dmarc_scan_result.spf.record_not_found
        ):
            result.spf_dmarc_scan_result.spf.valid = True

        random_token = os.urandom(8).hex()
        try:
            random_subdomain_has_mx_records = len(dns.resolver.resolve(random_token + "." + domain, "MX")) > 0
        except dns.resolver.NoAnswer:
            random_subdomain_has_mx_records = False
        except dns.resolver.NXDOMAIN:
            random_subdomain_has_mx_records = False

        if has_mx_records and random_subdomain_has_mx_records:
            # Some domains return a MX records for all subdomains, even nonexistent ones.
            # In that case we shouldn't expect a SPF record to exist on all of them.
            #
            # Therefore, let's check them only on the main domain - on all others,
            # it's allowed to skip them (but we should report if they're invalid)
            if (
                not is_main_domain(domain)
                and result.spf_dmarc_scan_result
                and result.spf_dmarc_scan_result.spf
                and result.spf_dmarc_scan_result.spf.record_not_found
            ):
                result.spf_dmarc_scan_result.spf.valid = True

        return result

    def run(self, current_task: Task) -> None:
        if current_task.get_payload("mail_domain"):
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        domain = current_task.get_payload(TaskType.DOMAIN)
        result = self.scan(current_task, domain)

        status_reasons: List[str] = []
        if (
            result.spf_dmarc_scan_result
            and result.spf_dmarc_scan_result.spf
            and not result.spf_dmarc_scan_result.spf.valid
        ):
            status_reasons.extend(result.spf_dmarc_scan_result.spf.errors)
        if (
            result.spf_dmarc_scan_result
            and result.spf_dmarc_scan_result.dmarc
            and not result.spf_dmarc_scan_result.dmarc.valid
        ):
            status_reasons.extend(result.spf_dmarc_scan_result.dmarc.errors)

        if status_reasons:
            status = TaskStatus.INTERESTING
            status_reason = "Found problems: " + ", ".join(sorted(status_reasons))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task, status=status, status_reason=status_reason, data=dataclasses.asdict(result)
        )


if __name__ == "__main__":
    MailDNSScanner().loop()
