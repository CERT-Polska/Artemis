from test.base import ArtemisModuleTestCase
from typing import NamedTuple

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
