from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.classifier import Classifier


class TestData(NamedTuple):
    raw: str
    expected: str
    type: TaskType


class ClassifierTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Classifier  # type: ignore

    def test_skipping_public_suffixes(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "gov.pl."})
        results = self.run_task(task)

        self.assertTasksEqual(results, [])

    def test_parsing(self) -> None:
        urls = [
            TestData("https://cert.pl", "cert.pl", TaskType.DOMAIN),
            TestData("http://cert.pl", "cert.pl", TaskType.DOMAIN),
            TestData("cert.pl", "cert.pl", TaskType.DOMAIN),
            TestData("cert.pl:8080", "cert.pl", TaskType.DOMAIN),
            TestData("ws://cert.pl", "cert.pl", TaskType.DOMAIN),
            TestData("root@cert.pl", "cert.pl", TaskType.DOMAIN),
            TestData("ssh://cert.pl", "cert.pl", TaskType.DOMAIN),
            TestData("ssh://127.0.0.1", "127.0.0.1", TaskType.IP),
            TestData("127.0.0.1:8080", "127.0.0.1", TaskType.IP),
        ]

        for entry in urls:
            self.karton.cache.flush()
            task = Task({"type": TaskType.NEW}, payload={"data": entry.raw})
            results = self.run_task(task)

            expected_task = Task(
                {"type": entry.type, "origin": Classifier.identity},
                payload={entry.type: entry.expected},
                payload_persistent={f"original_{entry.type.value}": entry.expected},
            )

            self.assertTasksEqual(results, [expected_task])

    def test_invalid_url(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "INVALID_DATA"})

        with self.assertRaises(ValueError):
            results = self.run_task(task)
            self.assertListEqual(results, [])
