from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.mail_dns_scanner import MailDNSScanner


class MailDNSScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = MailDNSScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: "test-smtp-server"})
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found problems: SPF record is not present, DMARC record is not present",
        )
        self.assertEqual(call.kwargs["data"].mail_server_found, True)
        self.assertEqual(call.kwargs["data"].spf_record_present, False)
