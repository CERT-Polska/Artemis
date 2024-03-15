from test.base import ArtemisModuleTestCase

from freezegun import freeze_time
from karton.core import Task
from retry import retry

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.wordpress_bruter import PASSWORDS, WordPressBruter


class WordPressBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = WordPressBruter  # type: ignore

    @freeze_time("2023-02-21")
    def test_getting_passwords_domain(self) -> None:
        passwords = self.karton.get_passwords(
            Task(
                headers={"type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
                payload={"url": "http://www.projectname.example.com"},
            )
        )
        self.assertEqual(
            passwords,
            PASSWORDS
            + [
                "projectname123",
                "projectname1",
                "projectname2023",
                "projectname2022",
                "projectname2021",
                "projectname2020",
            ],
        )

    def test_getting_passwords_ip(self) -> None:
        passwords = self.karton.get_passwords(
            Task(
                headers={"type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
                payload={"url": "http://127.0.0.1"},
            )
        )
        self.assertEqual(passwords, PASSWORDS)

    @retry(tries=3)
    def test_simple(self) -> None:
        task = Task(
            headers={"type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
            payload={"url": "http://test-wordpress-easy-password"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found working credentials for the WordPress admin: long_and_hard_to_guess_username:12345",
        )
        self.assertEqual(call.kwargs["data"], [("long_and_hard_to_guess_username", "12345")])
