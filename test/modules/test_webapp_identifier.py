from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Service, TaskType, WebApplication
from artemis.modules.webapp_identifier import WebappIdentifier


class TestData(NamedTuple):
    domain: str
    application: WebApplication


class WebappIdentifierTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = WebappIdentifier  # type: ignore

    def test_simple(self) -> None:
        data = [
            TestData("test-old-joomla", WebApplication.JOOMLA),
            TestData("test-old-wordpress", WebApplication.WORDPRESS),
        ]

        for entry in data:
            task = Task(
                {"type": TaskType.SERVICE, "service": Service.HTTP},
                payload={"host": entry.domain, "port": 80},
            )

            result = self.run_task(task)
            (task,) = result
            self.assertEqual(task.headers["webapp"], entry.application)
            self.assertEqual(task.payload["url"], f"http://{entry.domain}:80")
