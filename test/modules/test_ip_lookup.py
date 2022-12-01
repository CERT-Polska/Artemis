from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.ip_lookup import IPLookup


class TestData(NamedTuple):
    domain: str
    ip: str


class IPLookupTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = IPLookup  # type: ignore

    def test_simple(self) -> None:
        data = [
            TestData("lebihan.pl", "146.59.80.63"),
        ]

        for entry in data:
            task = Task(
                {"type": TaskType.DOMAIN},
                payload={TaskType.DOMAIN: entry.domain},
            )
            results = self.run_task(task)

            expected_task = Task(
                {"type": TaskType.NEW, "origin": IPLookup.identity},
                payload={"data": entry.ip},
            )
            self.assertTasksEqual(results, [expected_task])

    def test_invalid_url(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN},
            payload_persistent={TaskType.DOMAIN: "INVALID_DATA"},
        )

        results = self.run_task(task)
        self.assertListEqual(results, [])
