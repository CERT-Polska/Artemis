import logging
import unittest
from test.base import ArtemisModuleTestCase
from typing import NamedTuple
from unittest.mock import MagicMock

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.robots import RobotsScanner  # noqa: E402


class TestData(NamedTuple):
    host: str
    port: int
    ssl: bool
    task_type: TaskType


class RobotsTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = RobotsScanner  # type: ignore

    def test_robots(self) -> None:
        data = [
            TestData("test-robots-service", 80, False, TaskType.SERVICE),
        ]

        for entry in data:
            self.mock_db.reset_mock()
            task = Task(
                {"type": TaskType.SERVICE, "service": Service.HTTP},
                payload={
                    "host": entry.host,
                    "port": entry.port,
                    "ssl": entry.ssl,
                },
            )
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertEqual(
                call.kwargs["status_reason"],
                "Found potentially interesting paths (having directory index) in robots.txt: "
                "http://test-robots-service:80/secret-url/",
            )
            self.assertEqual(call.kwargs["data"]["result"]["status"], 200)
            self.assertEqual(
                call.kwargs["data"]["result"]["groups"],
                [
                    {
                        "user_agents": ["*"],
                        "disallow": ["/secret-url/", "/secret-url-noindex/", "/wp-includes/", "/icons/", "/"],
                        "allow": [],
                    }
                ],
            )
            self.assertEqual(
                [path["url"] for path in call.kwargs["data"]["result"]["found_urls"]],
                ["http://test-robots-service:80/secret-url/"],
            )


class RobotsParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = RobotsScanner.__new__(RobotsScanner)
        self.scanner.log = MagicMock(spec=logging.Logger)

    def test_normal_robots_txt(self) -> None:
        content = "User-agent: *\nDisallow: /admin/\nAllow: /public/\n"
        groups = self.scanner._parse_robots(content)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].user_agents, ["*"])
        self.assertEqual(groups[0].disallow, ["/admin/"])
        self.assertEqual(groups[0].allow, ["/public/"])

    def test_multiple_user_agents_in_group(self) -> None:
        content = "User-agent: Googlebot\nUser-agent: Bingbot\nDisallow: /private/\n"
        groups = self.scanner._parse_robots(content)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].user_agents, ["Googlebot", "Bingbot"])
        self.assertEqual(groups[0].disallow, ["/private/"])

    def test_disallow_rule_before_user_agent_does_not_crash(self) -> None:
        content = "Disallow: /early/\nUser-agent: *\nDisallow: /admin/\n"
        groups = self.scanner._parse_robots(content)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].disallow, ["/admin/"])
        self.scanner.log.warning.assert_called()

    def test_allow_rule_before_user_agent_does_not_crash(self) -> None:
        content = "Allow: /early/\nUser-agent: *\nDisallow: /private/\n"
        groups = self.scanner._parse_robots(content)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].disallow, ["/private/"])
        self.scanner.log.warning.assert_called()

    def test_empty_content(self) -> None:
        groups = self.scanner._parse_robots("")
        self.assertEqual(groups, [])
