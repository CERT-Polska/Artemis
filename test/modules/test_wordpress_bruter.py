from test.base import ArtemisModuleTestCase

from karton.core import Task
from retry import retry

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.wordpress_bruter import WordPressBruter


class WordPressBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = WordPressBruter  # type: ignore

    @retry(tries=3)
    def test_simple(self) -> None:
        self.setUp()  # @retry() will not rerun setUp

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
