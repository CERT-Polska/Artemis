import socket
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.ssh_bad_keys import SSHBadKeys


class TestSSHBadKeys(ArtemisModuleTestCase):
    karton_class = SSHBadKeys  # type: ignore

    def test_bad_key_detected(self) -> None:
        ip = socket.gethostbyname("test-ssh-with-bad-key")

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SSH},
            payload={"host": ip, "port": 22},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("known-bad SSH host key", call.kwargs["status_reason"])
        self.assertGreater(len(call.kwargs["data"].bad_keys), 0)

        bad_key = call.kwargs["data"].bad_keys[0]
        self.assertIn("rsa", bad_key.key_type)
        self.assertEqual(bad_key.check_name, "blocklist")

    def test_good_key_ok(self) -> None:
        ip = socket.gethostbyname("test-ssh-with-easy-password")

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SSH},
            payload={"host": ip, "port": 2222},
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
