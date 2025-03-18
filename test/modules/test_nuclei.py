from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei


class NucleiTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def test_403_bypass_workflow(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-403-bypass",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "[medium] http://test-php-403-bypass:80: 403 Forbidden Bypass Detection with Headers Detects potential 403 Forbidden bypass vulnerabilities by adding headers (e.g., X-Forwarded-For, X-Original-URL).\n",
        )

    def test_links(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-xss-but-not-on-homepage",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "[high] http://test-php-xss-but-not-on-homepage:80/xss.php: Top 38 Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter "
            "values in the server response via GET-requests., [medium] http://test-php-xss-but-not-on-homepage:80/xss.php: Fuzzing Parameters - Cross-Site Scripting Cross-site scripting "
            "was discovered via a search for reflected parameter values in the server response via GET-requests.\n",
        )
