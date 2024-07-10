import socket
from test.base import BaseReportingTest

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.ssh_bruter import SSHBruter
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class SSHBruterAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = SSHBruter  # type: ignore

    def test_ssh_with_easy_access(self) -> None:
        message = self._run_task_and_get_message(socket.gethostbyname("test-ssh-with-easy-password"))
        self.assertIn(
            "The following addresses contain SSH servers where simple login/password pair allows logging in:",
            message,
        )
        self.assertIn(
            "the following credentials allow logging in",
            message,
        )
        self.assertIn(f"ssh://{socket.gethostbyname('test-ssh-with-easy-password')}", message)

    def _run_task_and_get_message(self, host: str) -> str:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.SSH},
            payload={"host": host, "port": 2222},
            payload_persistent={"original_domain": host},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        data = {
            "created_at": None,
            "headers": {
                "receiver": "ssh_bruter",
            },
            "payload": {
                "last_domain": host,
                "host": host,
            },
            "payload_persistent": {
                "original_domain": host,
            },
            "status": "INTERESTING",
            "result": call.kwargs["data"],
        }

        reports = reports_from_task_result(data, Language.en_US)  # type: ignore
        message_template = self.generate_message_template()
        return message_template.render(
            {
                "data": {
                    "custom_template_arguments": {},
                    "contains_type": set([report.report_type for report in reports]),
                    "reports": reports,
                }
            }
        )
