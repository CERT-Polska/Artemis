#!/usr/bin/env python3
import socket
from smtplib import SMTP, SMTPServerDisconnected

import dns.name
import dns.resolver
from karton.core import Task
from pydantic import BaseModel

from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.resolvers import ip_lookup


class MailDNSScannerResult(BaseModel):
    mail_server_found = False
    spf_record_present = False
    spf_rejecting_all = False
    multiple_spf_records = False
    dmarc_record_present = False


class MailDNSScanner(ArtemisBase):
    """
    Checks if there is a mail server associated with the current domain and checks if SPF and DMARC records are present
    """

    identity = "mail_dns_scanner"
    filters = [{"type": TaskType.DOMAIN.value}]

    @staticmethod
    def is_smtp_server(host: str, port: int) -> bool:
        smtp = SMTP(timeout=1)
        try:
            smtp.connect(host, port=port)
            smtp.close()
            return True
        except socket.timeout:
            return False
        except ConnectionRefusedError:
            return False
        except SMTPServerDisconnected:
            return False

    def scan(self, current_task: Task, domain: str) -> MailDNSScannerResult:
        result = MailDNSScannerResult()

        # Try to find an SMTP for current domain
        try:
            domain_mx_records = dns.resolver.resolve(domain, "MX")
            for domain_mx_record in domain_mx_records:
                exchange = str(domain_mx_record.exchange).removesuffix(".")
                result.mail_server_found = True
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
            else:
                return result
        except dns.resolver.NXDOMAIN:
            return result

        # Check SPF
        try:
            domain_txt_records = dns.resolver.resolve(domain, "TXT")
            for domain_txt_record in domain_txt_records:
                raw_domain_txt_record = str(domain_txt_record).strip('"')
                if raw_domain_txt_record.startswith("v=spf1"):
                    result.multiple_spf_records = result.spf_record_present
                    result.spf_record_present = True
                    result.spf_rejecting_all = any(x in raw_domain_txt_record for x in ["-all", "~all"])
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            # For example the Docker dns server returns NXDOMAIN in such case.
            pass

        # Check DMARC
        domain_dmarc_candidate = dns.name.from_text(domain)
        while not result.dmarc_record_present and str(domain_dmarc_candidate) != ".":
            try:
                domain_txt_records = dns.resolver.resolve("_dmarc." + str(domain_dmarc_candidate), "TXT")
                for domain_txt_record in domain_txt_records:
                    raw_domain_txt_record = str(domain_txt_record).strip('"')
                    result.dmarc_record_present = result.dmarc_record_present or raw_domain_txt_record.startswith(
                        "v=DMARC1"
                    )
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            domain_dmarc_candidate = domain_dmarc_candidate.parent()

        return result

    def run(self, current_task: Task) -> None:
        if current_task.get_payload("mail_domain"):
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        domain = current_task.get_payload(TaskType.DOMAIN)
        result = self.scan(current_task, domain)

        status = TaskStatus.OK
        status_reason = None
        if result.mail_server_found:
            status_reasons = []
            if not result.spf_record_present:
                status_reasons.append("SPF record is not present")
            if result.multiple_spf_records:
                status_reasons.append("multiple SPF records are present")
            if result.spf_record_present and not result.spf_rejecting_all:
                status_reasons.append("SPF record doesn't contain the 'reject all' directive")
            if not result.dmarc_record_present:
                status_reasons.append("DMARC record is not present")
            if status_reasons:
                status = TaskStatus.INTERESTING
                status_reason = "Found problems: " + ", ".join(sorted(status_reasons))
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    MailDNSScanner().loop()
