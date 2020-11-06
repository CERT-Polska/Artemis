from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Application, Service, TaskType
from artemis.modules.webapp_identifier import WebappIdentifier


class TestData(NamedTuple):
    domain: str
    application: Application


class WebappIdentifierTest(ArtemisModuleTestCase):
    karton_class = WebappIdentifier

    def test_simple(self) -> None:
        data = [
            TestData("test-old-joomla", Application.JOOMLA),
            TestData("test-old-wordpress", Application.WORDPRESS),
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
