from test.base import ArtemisModuleTestCase
from typing import List, NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.classifier import Classifier


class ExpectedTaskData(NamedTuple):
    task_type: TaskType
    data: str


class TestData(NamedTuple):
    raw: str
    expected: List[ExpectedTaskData]


class ClassifierTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Classifier  # type: ignore

    def test_skipping_public_suffixes(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "gov.pl."})
        results = self.run_task(task)

        self.assertTasksEqual(results, [])

    def test_parsing(self) -> None:
        urls = [
            TestData("https://cert.pl", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("http://cert.pl", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("cert.pl", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("cert.pl:8080", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("ws://cert.pl", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("root@cert.pl", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("ssh://cert.pl", [ExpectedTaskData(TaskType.DOMAIN, "cert.pl")]),
            TestData("ssh://127.0.0.1", [ExpectedTaskData(TaskType.IP, "127.0.0.1")]),
            TestData("127.0.0.1:8080", [ExpectedTaskData(TaskType.IP, "127.0.0.1")]),
            TestData(
                "127.0.0.1-127.0.0.5",
                [
                    ExpectedTaskData(TaskType.IP, "127.0.0.1"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.2"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.3"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.4"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.5"),
                ],
            ),
            TestData(
                "127.0.0.0/30",
                [
                    ExpectedTaskData(TaskType.IP, "127.0.0.0"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.1"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.2"),
                    ExpectedTaskData(TaskType.IP, "127.0.0.3"),
                ],
            ),
        ]

        for entry in urls:
            self.karton.cache.flush()
            task = Task({"type": TaskType.NEW}, payload={"data": entry.raw})
            results = self.run_task(task)

            expected_tasks = [
                Task(
                    {"type": item.task_type, "origin": Classifier.identity},
                    payload={"domain": item.data, "last_domain": item.data}
                    if item.task_type == TaskType.DOMAIN
                    else {"ip": item.data},
                    payload_persistent={f"original_{item.task_type.value}": item.data},
                )
                for item in entry.expected
            ]

            for i in range(len(results)):
                del results[i].payload["created_at"]
            self.assertTasksEqual(results, expected_tasks)

    def test_invalid_url(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "INVALID_DATA"})

        with self.assertRaises(ValueError):
            results = self.run_task(task)
            self.assertListEqual(results, [])
