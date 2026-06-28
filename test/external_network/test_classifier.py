from socket import gethostbyname
from test.base import ArtemisModuleTestCase
from typing import Any, Dict, List, NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.classifier import Classifier


class ExpectedTaskData(NamedTuple):
    headers: Dict[str, Any]
    payload: Dict[str, Any]
    payload_persistent: Dict[str, Any]


class TestData(NamedTuple):
    raw: str
    expected: List[ExpectedTaskData]


class ClassifierTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Classifier  # type: ignore

    def test_parsing(self) -> None:
        cert_ip = gethostbyname("cert.pl")

        entries = [
            TestData(
                "cert.pl:80",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": "cert.pl", "port": 80, "last_domain": "cert.pl", "ssl": False},
                        payload_persistent={"original_domain": "cert.pl", "original_target": "cert.pl:80"},
                    ),
                ],
            ),
            TestData(
                f"{cert_ip}:80",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": cert_ip, "port": 80, "ssl": False},
                        payload_persistent={"original_ip": cert_ip, "original_target": f"{cert_ip}:80"},
                    ),
                ],
            ),
            TestData(
                "cert.pl",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain_that_may_not_exist"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl", "original_target": "cert.pl"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl", "original_target": "cert.pl"},
                    ),
                ],
            ),
            TestData(
                "CERT.pl",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain_that_may_not_exist"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl", "original_target": "CERT.pl"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl", "original_target": "CERT.pl"},
                    ),
                ],
            ),
        ]

        for entry in entries:
            self.karton.cache.flush()
            task = Task({"type": TaskType.NEW}, payload={"data": entry.raw})
            results = self.run_task(task)

            expected_tasks = [
                Task(
                    headers=item.headers,
                    payload=item.payload,
                    payload_persistent=item.payload_persistent,
                )
                for item in entry.expected
            ]

            for i in range(len(results)):
                del results[i].payload["created_at"]
            self.assertTasksEqual(results, expected_tasks)
