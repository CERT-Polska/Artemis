from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.wp_scanner import WordPressScanner


class WordPressScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = WordPressScanner  # type: ignore

    def test_detecting_old_version(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
            payload={"url": "http://test-old-wordpress/"},
        )

        # We perform the check twice because this task caches WordPress API responses.
        # Therefore let's check whether the flow with and without cache is correct.
        for _ in range(2):
            self.mock_db.reset_mock()
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertEqual(
                call.kwargs["status_reason"],
                "Found WordPress problems: WordPress 5.9.3 is considered insecure, WordPress 5.9.3 is old",
            )
            self.assertEqual(
                call.kwargs["data"],
                {"wp_version": "5.9.3", "wp_version_insecure": True, "wp_version_old": True},
            )
