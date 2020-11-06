from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.reverse_dns_lookup import ReverseDNSLookup


class TestData(NamedTuple):
    ip: str
    domain: str


class ReverseDNSLookupTest(ArtemisModuleTestCase):
    karton_class = ReverseDNSLookup

    def test_simple(self) -> None:
        data = [
            TestData("193.0.96.129", "students.mimuw.edu.pl"),
        ]

        for entry in data:
            task = Task(
                {"type": TaskType.IP},
                payload={TaskType.IP: entry.ip},
            )
            results = self.run_task(task)

            expected_task = Task(
                {"type": TaskType.NEW, "origin": self.karton_class.identity},
                payload={"data": entry.domain},
            )
            self.assertTasksEqual(results, [expected_task])
