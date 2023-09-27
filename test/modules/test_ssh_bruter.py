import socket
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.ssh_bruter import SSHBruter


class TestSSHBruter(ArtemisModuleTestCase):
    karton_class = SSHBruter  # type: ignore

    def test_simple(self) -> None:
        ip = socket.gethostbyname("test-ssh-with-easy-password")

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SSH},
            payload={"host": ip, "port": 2222},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found working credentials for SSH connection: user:password")
        self.assertEqual(call.kwargs["data"].credentials, [("user", "password")])
