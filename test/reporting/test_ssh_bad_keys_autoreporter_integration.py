import socket
from test.base import BaseReportingTest

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.ssh_bad_keys import SSHBadKeys
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class SSHBadKeysAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = SSHBadKeys  # type: ignore

    def test_bad_key_report(self) -> None:
        message = self._run_task_and_get_message(socket.gethostbyname("test-ssh-with-bad-key"))
        self.assertIn(
            "The following addresses have SSH servers with known-bad host keys",
            message,
        )
        self.assertIn(f"ssh://{socket.gethostbyname('test-ssh-with-bad-key')}", message)

    def _run_task_and_get_message(self, host: str) -> str:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.SSH},
            payload={"host": host, "port": 22},
            payload_persistent={"original_domain": host},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        data = {
            "created_at": None,
            "headers": {
                "receiver": "ssh_bad_keys",
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
