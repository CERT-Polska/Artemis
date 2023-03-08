from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.gau import GAU


class TestData(NamedTuple):
    domain: str
    expected_subdomain: str


class GAUTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = GAU  # type: ignore

    def test_simple(self) -> None:
        data = [
            TestData("cert.pl", "nomoreransom.cert.pl"),
        ]

        for entry in data:
            task = Task(
                {"type": TaskType.DOMAIN},
                payload={TaskType.DOMAIN: entry.domain},
            )
            results = self.run_task(task)

            found = any(item.payload["domain"] == entry.expected_subdomain for item in results)
            self.assertTrue(found)
