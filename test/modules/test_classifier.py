from test.base import ArtemisModuleTestCase
from typing import Any, Dict, List, NamedTuple
from unittest.mock import patch

from karton.core import Task

from artemis import direct_url_scanning
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
        # Root URLs are supported - the scheme selects the service
        self.assertTrue(Classifier.is_supported("http://example.com"))
        self.assertTrue(Classifier.is_supported("http://cert.pl"))
        self.assertTrue(Classifier.is_supported("https://CERT.pl"))
        self.assertTrue(Classifier.is_supported("https://example.com:8443/"))
        self.assertTrue(Classifier.is_supported("ssh://127.0.0.1"))
        self.assertTrue(Classifier.is_supported("ssh://example.com:22/"))
        self.assertTrue(Classifier.is_supported("http://[::1]:8080/"))
        # URLs with userinfo, an unmapped scheme, a missing host, a path or a query are rejected
        self.assertFalse(Classifier.is_supported("http://a:b@example.com"))
        self.assertFalse(Classifier.is_supported("ws://cert.pl"))
        self.assertFalse(Classifier.is_supported("gopher://cert.pl"))
        self.assertFalse(Classifier.is_supported("http://"))
        self.assertFalse(Classifier.is_supported("http://cert.pl/admin"))
        self.assertFalse(Classifier.is_supported("http://cert.pl/?q=1"))
        # Malformed scheme separators are not URLs and aren't valid host:port either
        self.assertFalse(Classifier.is_supported("http:/cert.pl"))
        self.assertFalse(Classifier.is_supported("http:cert.pl"))
        # Non-URL inputs keep their existing behaviour
        self.assertTrue(Classifier.is_supported("cert.pl"))
        self.assertTrue(Classifier.is_supported("[::1]:2"))
        self.assertTrue(Classifier.is_supported("[::1]"))
        self.assertFalse(Classifier.is_supported("[::1]:a"))
        self.assertTrue(Classifier.is_supported("cert.pl:8080"))
        self.assertFalse(Classifier.is_supported("cert.pl:8080port"))
        self.assertTrue(Classifier.is_supported("1.2.3.4:56"))
        self.assertTrue(Classifier.is_supported("CERT.pl"))
        self.assertFalse(Classifier.is_supported("root@cert.pl"))

    def test_is_scannable_url(self) -> None:
        # Root URLs that map to a service are accepted as direct scan targets
        self.assertTrue(direct_url_scanning.is_scannable_url("http://example.com"))
        self.assertTrue(direct_url_scanning.is_scannable_url("https://example.com:8443/"))
        self.assertTrue(direct_url_scanning.is_scannable_url("ssh://example.com:22/"))
        # Domains and IPs (with or without a port) are supported targets but not direct scan URLs
        self.assertFalse(direct_url_scanning.is_scannable_url("cert.pl"))
        self.assertFalse(direct_url_scanning.is_scannable_url("cert.pl:8080"))
        self.assertFalse(direct_url_scanning.is_scannable_url("1.2.3.4:56"))
        # Non-root URLs, unmapped schemes and malformed separators are not accepted
        self.assertFalse(direct_url_scanning.is_scannable_url("http://cert.pl/admin"))
        self.assertFalse(direct_url_scanning.is_scannable_url("ws://cert.pl"))
        self.assertFalse(direct_url_scanning.is_scannable_url("http:/cert.pl"))
        self.assertFalse(direct_url_scanning.is_scannable_url("http:cert.pl"))

    def test_parsing(self) -> None:
        entries = [
            TestData(
                "127.0.0.1-127.0.0.5",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.1"},
                        payload_persistent={
                            "original_ip": "127.0.0.1",
                            "original_ip_range": "127.0.0.1-127.0.0.5",
                            "original_target": "127.0.0.1-127.0.0.5",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.2"},
                        payload_persistent={
                            "original_ip": "127.0.0.2",
                            "original_ip_range": "127.0.0.1-127.0.0.5",
                            "original_target": "127.0.0.1-127.0.0.5",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.3"},
                        payload_persistent={
                            "original_ip": "127.0.0.3",
                            "original_ip_range": "127.0.0.1-127.0.0.5",
                            "original_target": "127.0.0.1-127.0.0.5",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.4"},
                        payload_persistent={
                            "original_ip": "127.0.0.4",
                            "original_ip_range": "127.0.0.1-127.0.0.5",
                            "original_target": "127.0.0.1-127.0.0.5",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.5"},
                        payload_persistent={
                            "original_ip": "127.0.0.5",
                            "original_ip_range": "127.0.0.1-127.0.0.5",
                            "original_target": "127.0.0.1-127.0.0.5",
                        },
                    ),
                ],
            ),
            TestData(
                "127.0.0.0/255.255.255.252",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.0"},
                        payload_persistent={
                            "original_ip": "127.0.0.0",
                            "original_ip_range": "127.0.0.0/255.255.255.252",
                            "original_target": "127.0.0.0/255.255.255.252",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.1"},
                        payload_persistent={
                            "original_ip": "127.0.0.1",
                            "original_ip_range": "127.0.0.0/255.255.255.252",
                            "original_target": "127.0.0.0/255.255.255.252",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.2"},
                        payload_persistent={
                            "original_ip": "127.0.0.2",
                            "original_ip_range": "127.0.0.0/255.255.255.252",
                            "original_target": "127.0.0.0/255.255.255.252",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.3"},
                        payload_persistent={
                            "original_ip": "127.0.0.3",
                            "original_ip_range": "127.0.0.0/255.255.255.252",
                            "original_target": "127.0.0.0/255.255.255.252",
                        },
                    ),
                ],
            ),
            TestData(
                "127.0.0.0/30",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.0"},
                        payload_persistent={
                            "original_ip": "127.0.0.0",
                            "original_ip_range": "127.0.0.0/30",
                            "original_target": "127.0.0.0/30",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.1"},
                        payload_persistent={
                            "original_ip": "127.0.0.1",
                            "original_ip_range": "127.0.0.0/30",
                            "original_target": "127.0.0.0/30",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.2"},
                        payload_persistent={
                            "original_ip": "127.0.0.2",
                            "original_ip_range": "127.0.0.0/30",
                            "original_target": "127.0.0.0/30",
                        },
                    ),
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "ip"},
                        payload={"ip": "127.0.0.3"},
                        payload_persistent={
                            "original_ip": "127.0.0.3",
                            "original_ip_range": "127.0.0.0/30",
                            "original_target": "127.0.0.0/30",
                        },
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

    def test_url_emission(self) -> None:
        entries = [
            TestData(
                "http://example.com:8080/",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": "example.com", "port": 8080, "ssl": False, "last_domain": "example.com"},
                        payload_persistent={
                            "original_domain": "example.com",
                            "original_target": "http://example.com:8080/",
                        },
                    ),
                ],
            ),
            TestData(
                "https://example.com/",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": "example.com", "port": 443, "ssl": True, "last_domain": "example.com"},
                        payload_persistent={
                            "original_domain": "example.com",
                            "original_target": "https://example.com/",
                        },
                    ),
                ],
            ),
            TestData(
                "ssh://example.com:22/",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "ssh"},
                        payload={"host": "example.com", "port": 22, "ssl": False, "last_domain": "example.com"},
                        payload_persistent={
                            "original_domain": "example.com",
                            "original_target": "ssh://example.com:22/",
                        },
                    ),
                ],
            ),
            TestData(
                # An IP host has no domain, so the task carries no last_domain and uses original_ip.
                "http://1.1.1.1/",
                [
                    ExpectedTaskData(
                        headers={"origin": "classifier", "type": "service", "service": "http"},
                        payload={"host": "1.1.1.1", "port": 80, "ssl": False},
                        payload_persistent={
                            "original_ip": "1.1.1.1",
                            "original_target": "http://1.1.1.1/",
                        },
                    ),
                ],
            ),
        ]

        for entry in entries:
            self.karton.cache.flush()
            # The scheme tells us the service, so the URL path must not shell out to fingerprintx.
            with patch("artemis.modules.classifier.check_output_log_on_error") as mock_fingerprintx:
                task = Task({"type": TaskType.NEW}, payload={"data": entry.raw})
                results = self.run_task(task)
                mock_fingerprintx.assert_not_called()

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

    def test_url_with_path_is_unsupported(self) -> None:
        task = Task({"type": TaskType.NEW}, payload={"data": "http://cert.pl/admin"})

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status_reason"], "Unsupported data: http://cert.pl/admin")
