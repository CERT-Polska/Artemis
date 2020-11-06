from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Application, TaskStatus
from artemis.modules.joomla_scanner import JoomlaScanner


class JoomlaScannerTest(ArtemisModuleTestCase):
    karton_class = JoomlaScanner

    def test_simple(self) -> None:
        task = Task(
            {"webapp": Application.JOOMLA},
            payload={"url": "http://test-old-joomla/"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found problems: Joomla version is too old: 3.10.11")
        self.assertEqual(call.kwargs["data"], {"joomla_version": "3.10.11"})
