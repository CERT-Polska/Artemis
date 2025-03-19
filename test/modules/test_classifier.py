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

    def test_skipping_public_suffixes(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "gov.pl."})
        results = self.run_task(task)

        self.assertTasksEqual(results, [])

    def test_support(self) -> None:
        # URLs are not supported
        self.assertFalse(Classifier.is_supported("http://example.com"))
        self.assertFalse(Classifier.is_supported("http://a:b@example.com"))
        self.assertTrue(Classifier.is_supported("cert.pl"))
        self.assertTrue(Classifier.is_supported("[::1]:2"))
        self.assertTrue(Classifier.is_supported("[::1]"))
        self.assertFalse(Classifier.is_supported("[::1]:a"))
        self.assertTrue(Classifier.is_supported("cert.pl:8080"))
        self.assertFalse(Classifier.is_supported("cert.pl:8080port"))
        self.assertTrue(Classifier.is_supported("1.2.3.4:56"))
        self.assertTrue(Classifier.is_supported("CERT.pl"))
        self.assertFalse(Classifier.is_supported("https://CERT.pl"))
        self.assertFalse(Classifier.is_supported("http://cert.pl"))
        self.assertFalse(Classifier.is_supported("ws://cert.pl"))
        self.assertFalse(Classifier.is_supported("root@cert.pl"))
        self.assertFalse(Classifier.is_supported("ssh://127.0.0.1"))

    def test_parsing(self) -> None:
        cert_ip = gethostbyname("cert.pl")

        entries = [
            TestData(
                "cert.pl:80",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": "cert.pl", "port": 80, "last_domain": "cert.pl", "ssl": False},
                        payload_persistent={"original_domain": "cert.pl"},
                    ),
                ],
            ),
            TestData(
                f"{cert_ip}:80",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": cert_ip, "port": 80, "ssl": False},
                        payload_persistent={"original_ip": cert_ip},
                    ),
                ],
            ),
            TestData(
                "cert.pl",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain_that_may_not_exist"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl"},
                    ),
                ],
            ),
            TestData(
                "CERT.pl",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain_that_may_not_exist"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "domain"},
                        payload={"domain": "cert.pl", "last_domain": "cert.pl"},
                        payload_persistent={"original_domain": "cert.pl"},
                    ),
                ],
            ),
            TestData(
                "127.0.0.1-127.0.0.5",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.1"},
                        payload_persistent={"original_ip": "127.0.0.1", "original_ip_range": "127.0.0.1-127.0.0.5"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.2"},
                        payload_persistent={"original_ip": "127.0.0.2", "original_ip_range": "127.0.0.1-127.0.0.5"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.3"},
                        payload_persistent={"original_ip": "127.0.0.3", "original_ip_range": "127.0.0.1-127.0.0.5"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.4"},
                        payload_persistent={"original_ip": "127.0.0.4", "original_ip_range": "127.0.0.1-127.0.0.5"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.5"},
                        payload_persistent={"original_ip": "127.0.0.5", "original_ip_range": "127.0.0.1-127.0.0.5"},
                    ),
                ],
            ),
            TestData(
                "127.0.0.0/30",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.0"},
                        payload_persistent={"original_ip": "127.0.0.0", "original_ip_range": "127.0.0.0/30"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.1"},
                        payload_persistent={"original_ip": "127.0.0.1", "original_ip_range": "127.0.0.0/30"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.2"},
                        payload_persistent={"original_ip": "127.0.0.2", "original_ip_range": "127.0.0.0/30"},
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.3"},
                        payload_persistent={"original_ip": "127.0.0.3", "original_ip_range": "127.0.0.0/30"},
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

    def test_invalid_data(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "INVALID_DATA"})

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status_reason"], "Unsupported data: invalid_data")
