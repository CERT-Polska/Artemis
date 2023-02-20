from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.crtsh import CrtshScanner


class TestData(NamedTuple):
    domain: str
    expected_subdomain: str


class CrtshScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = CrtshScanner  # type: ignore

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
                if item.payload["domain"] == entry.expected_subdomain:
                    found = True
            self.assertTrue(found)
