from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.crtsh import CrtshScanner


class TestData(NamedTuple):
    domain: str
    expected_subdomain: str


class CrtshScannerTest(ArtemisModuleTestCase):
    karton_class = CrtshScanner

    def test_simple(self) -> None:
        data = [
            TestData("cert.pl", "ci.drakvuf.cert.pl"),
        ]

        for entry in data:
            task = Task(
                {"type": TaskType.DOMAIN},
                payload={TaskType.DOMAIN: entry.domain},
            )
            results = self.run_task(task)

            found = False
            for item in results:
                if item.payload["data"] == entry.expected_subdomain:
                    found = True
            self.assertTrue(found)
