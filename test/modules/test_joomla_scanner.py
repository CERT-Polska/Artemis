from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.joomla_scanner import JoomlaScanner


class JoomlaScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = JoomlaScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP, "webapp": WebApplication.JOOMLA},
            payload={"url": "http://test-old-joomla/"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found problems: Joomla version is too old: 4.0.5",
        )
        self.assertEqual(
            call.kwargs["data"],
            {"joomla_version": "4.0.5", "joomla_version_is_too_old": True},
        )
