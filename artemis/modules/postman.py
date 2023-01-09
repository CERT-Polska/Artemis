#!/usr/bin/env python3
from smtplib import (
    SMTP,
    SMTPDataError,
    SMTPHeloError,
    SMTPNotSupportedError,
    SMTPRecipientsRefused,
    SMTPSenderRefused,
)
from typing import Optional
from uuid import uuid4

from karton.core import Task
from pydantic import BaseModel

from artemis import request_limit
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase


class PostmanResult(BaseModel):
    open_relay = False
    unauthorized_local_from: Optional[str] = None


class Postman(ArtemisBase):
    """
    Collects `service: SMTP` and tests if it verifies credentials,
    as well as trying out open relay.
    """

    identity = "postman"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.SMTP},
    ]

    @staticmethod
    def _create_email(addr_from: str, addr_to: str, test_type: str) -> str:
        token = str(uuid4())
        message = str()
        message += f"From: {addr_from}\n"
        message += f"To: {addr_to}\n"
        message += f"This is an {test_type} SMTP test\n"
        message += f"{token}\n"
        return message

    @staticmethod
    def _check_open_relay(host: str, port: int) -> bool:
        """
        Tests if SMTP server allows sending as any address to any address.
        """
        try:
            local_hostname = Config.POSTMAN_MAIL_FROM.split("@")[1]
            request_limit.limit_requests_for_host(host)
            with SMTP(host, port, local_hostname=local_hostname, timeout=Config.REQUEST_TIMEOUT_SECONDS) as smtp:
                smtp.set_debuglevel(1)
                smtp.sendmail(
                    Config.POSTMAN_MAIL_FROM,
                    Config.POSTMAN_MAIL_TO,
                    Postman._create_email(Config.POSTMAN_MAIL_FROM, Config.POSTMAN_MAIL_TO, "open-relay"),
                )
        except (SMTPHeloError, SMTPNotSupportedError):
            return False
        except (SMTPSenderRefused, SMTPDataError):
            return False
        except (SMTPRecipientsRefused, SMTPDataError):
            return False

        return True

    @staticmethod
    def _check_outgoing_email(domain: str, host: str, port: int) -> bool:
        """
        Tests if SMTP server allows sending as domain to any address.
        """
        try:
            request_limit.limit_requests_for_host(host)
            with SMTP(host, port, timeout=Config.REQUEST_TIMEOUT_SECONDS) as smtp:
                smtp.set_debuglevel(1)
                mail_from = f"root@{domain}"
                smtp.sendmail(
                    mail_from, Config.POSTMAN_MAIL_TO, Postman._create_email(mail_from, Config.POSTMAN_MAIL_TO, "auth")
                )
        except (SMTPHeloError, SMTPNotSupportedError):
            return False
        except (SMTPSenderRefused, SMTPDataError):
            return False
        except (SMTPRecipientsRefused, SMTPDataError):
            return False

        return True

    def run(self, current_task: Task) -> None:
        result = PostmanResult()

        # This is the root domain for our task, if present - the one that was provided
        # on the "add URLs" page.
        original_domain = current_task.get_payload("original_domain")

        # If the host is a MX for a domain found by mail_dns_scanner, this is the domain
        # (it may be different from original_domain if e.g. original_domain led to the finding
        # of a subdomain and mail_dns_scanner was ran on that subdomain).
        mail_domain = current_task.get_payload("mail_domain")

        host = current_task.get_payload("host")
        port = current_task.get_payload("port")

        if original_domain:
            if self._check_outgoing_email(original_domain, host, port):
                result.unauthorized_local_from = original_domain

        if mail_domain:
            if self._check_outgoing_email(mail_domain, host, port):
                result.unauthorized_local_from = mail_domain

        # Because SERVICE tasks would get emitted for the domain and all its IPs, we will
        # test outgoing e-mail for @domain and @ip e-mails.
        if self._check_outgoing_email(host, host, port):
            result.unauthorized_local_from = host

        result.open_relay = self._check_open_relay(host, port)

        found_problems = []
        if result.unauthorized_local_from:
            found_problems.append(
                f"possible to send e-mails without autorisation (from @{result.unauthorized_local_from})"
            )
        if result.open_relay:
            found_problems.append("the server is an open relay")

        if found_problems:
            status = TaskStatus.INTERESTING
            status_reason = "Found problems: " + ", ".join(sorted(found_problems))
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    if not Config.POSTMAN_MAIL_FROM or not Config.POSTMAN_MAIL_TO:
        raise Exception("Missing env variables")

    Postman().loop()
