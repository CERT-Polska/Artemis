from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, WebApplication
from artemis.modules.wp_scanner import WordPressScanner


class WordPressScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = WordPressScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"webapp": WebApplication.WORDPRESS},
            payload={"url": "http://test-old-wordpress/"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found WordPress problems: version is too old: 5.9")
        self.assertEqual(call.kwargs["data"], {"wp_version": "5.9.3", "wp_plugins": []})
