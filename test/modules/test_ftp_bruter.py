from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.ftp_bruter import FTPBruter


class FTPBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = FTPBruter  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.FTP},
            payload={"host": "test-ftp-server-with-easy-password", "port": 21},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found working credentials for the FTP server: admin:12345, The credentials allow creating files.",
        )
        self.assertEqual(call.kwargs["data"].credentials, [("admin", "12345")])
