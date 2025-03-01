import datetime
import unittest.mock
from test.base import ArtemisModuleTestCase, KartonBackendMockWithRedis

from freezegun import freeze_time
from karton.core import Task
from karton.core.test import ConfigMock

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.joomla_scanner import JoomlaScanner


class JoomlaScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = JoomlaScanner  # type: ignore
    # Copied and adapted from MIT-licensed https://github.com/endoflife-date/endoflife.date
    endoflife_data = [
        {
            "releases": [
                {
                    "releaseCycle": "5",
                    "releaseDate": datetime.date(2023, 10, 14),
                    "support": True,
                    "eol": datetime.date(2027, 10, 19),
                    "latest": "5.0.1",
                    "latestReleaseDate": datetime.date(2023, 11, 24),
                    "link": "https://www.joomla.org/announcements/release-news/5900-joomla-5-0-and-joomla-4-4-are-here",
                },
                {
                    "releaseCycle": "4",
                    "releaseDate": datetime.date(2021, 8, 17),
                    "support": datetime.date(2024, 10, 17),
                    "eol": datetime.date(2025, 10, 17),
                    "latest": "4.4.1",
                    "latestReleaseDate": datetime.date(2023, 11, 23),
                },
                {
                    "releaseCycle": "3",
                    "releaseDate": datetime.date(2012, 9, 27),
                    "support": datetime.date(2021, 8, 17),
                    "eol": datetime.date(2023, 8, 17),
                    "latest": "3.10.12",
                    "latestReleaseDate": datetime.date(2023, 7, 8),
                },
            ],
        }
    ]

    @freeze_time("2023-02-21")
    def test_is_newer_version_available(self) -> None:
        with unittest.mock.patch("yaml.load_all", return_value=self.endoflife_data.__iter__()):
            # Recreate the karton with mocked endoflife data
            self.karton = self.karton_class(  # type: ignore
                config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=self.mock_db  # type: ignore
            )

            self.assertTrue(self.karton.is_version_obsolete("2.8.6"))
            self.assertTrue(self.karton.is_version_obsolete("2.99999.99999"))

            self.assertTrue(self.karton.is_version_obsolete("3.10.11"))
            self.assertFalse(self.karton.is_version_obsolete("3.10.12"))
            self.assertTrue(self.karton.is_version_obsolete("4.0.0"))
            self.assertFalse(self.karton.is_version_obsolete("4.4.1"))
            self.assertFalse(self.karton.is_version_obsolete("4.99999.99999"))

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
