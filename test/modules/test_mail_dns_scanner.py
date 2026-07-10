from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.mail_dns_scanner import MailDNSScanner


class MailDNSScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = MailDNSScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: "test-smtp-server.artemis"})
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found problems: Problem for server test-smtp-server.artemis port 25: STARTTLS not supported on test-smtp-server.artemis MX server, "
            "Problem for server test-smtp-server.artemis port 465: Connection refused, Problem for server test-smtp-server.artemis port 587: Connection refused, "
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the possibility of successful "
            "e-mail message spoofing., Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC to decrease the "
            "possibility of successful e-mail message spoofing.",
        )
        self.assertEqual(call.kwargs["data"]["spf_dmarc_scan_result"]["dmarc"]["valid"], False)
        self.assertEqual(call.kwargs["data"]["spf_dmarc_scan_result"]["spf"]["valid"], True)
