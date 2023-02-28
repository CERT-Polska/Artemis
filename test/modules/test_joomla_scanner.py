from test.base import ArtemisModuleTestCase

import requests_mock
from karton.core import Task

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.joomla_scanner import JoomlaScanner


class JoomlaScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = JoomlaScanner  # type: ignore

    def test_is_version_old(self) -> None:
        with requests_mock.Mocker() as requests_mocker:
            requests_mocker.get(
                "https://api.github.com/repos/joomla/joomla-cms/releases",
                json=[
                    {
                        "tag_name": "4.3.0",
                        "published_at": "2023-02-21T16:00:00Z",
                    },
                    {
                        "tag_name": "3.10.11",
                        "published_at": "2023-02-21T16:00:00Z",
                    },
                ],
            )

        self.assertTrue(self.karton.is_version_old("2.8.6"))
        self.assertTrue(self.karton.is_version_old("2.99999.99999"))
        self.assertTrue(self.karton.is_version_old("3.10.10"))
        self.assertFalse(self.karton.is_version_old("3.10.11"))
        self.assertTrue(self.karton.is_version_old("4.0.0"))
        self.assertFalse(self.karton.is_version_old("4.3.0"))
        self.assertFalse(self.karton.is_version_old("4.99999.99999"))

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP, "webapp": WebApplication.JOOMLA},
            payload={"url": "http://test-old-joomla/"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found problems: Joomla version is too old: 4.0.5")
        self.assertEqual(call.kwargs["data"], {"joomla_version": "4.0.5", "joomla_version_is_too_old": True})
