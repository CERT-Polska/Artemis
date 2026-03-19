from socket import gethostbyname
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.port_scanner import PortScanner


class PortScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = PortScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-redis"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "Found ports: 6379 (service: redis ssl: False, version: N/A)")
        self.assertEqual(
            list(call.kwargs["data"].values()), [{"6379": {"service": "redis", "ssl": False, "version": "N/A"}}]
        )

    def test_multiple(self) -> None:
        # Makes sure that the caching mechanism doesn't prevent returning correct results
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-redis"},
        )
        self.run_task(task)
        self.run_task(task)
        call1, call2 = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call1.kwargs["status_reason"], "Found ports: 6379 (service: redis ssl: False, version: N/A)")
        self.assertEqual(call2.kwargs["status_reason"], "Found ports: 6379 (service: redis ssl: False, version: N/A)")

    def test_http_detection(self) -> None:
        """Full pipeline (naabu → fingerprintx/fallback → result) detects HTTP on test-nginx."""
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-nginx"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        port_data = list(call.kwargs["data"].values())[0]
        self.assertIn("80", port_data)
        self.assertEqual(port_data["80"]["service"], "http")
        self.assertFalse(port_data["80"]["ssl"])

    def test_non_http_service_detected(self) -> None:
        """Full pipeline correctly identifies non-HTTP services (redis) via fingerprintx."""
        task = Task(
            {"type": TaskType.IP},
            payload={TaskType.IP: gethostbyname("test-redis")},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        port_data = list(call.kwargs["data"].values())[0]
        self.assertIn("6379", port_data)
        self.assertEqual(port_data["6379"]["service"], "redis")
        # Redis is not HTTP — fallback should not have overridden fingerprintx
        self.assertFalse(port_data["6379"]["ssl"])

    def test_no_ssl_against_sni(self) -> None:
        host = gethostbyname("test-nginx-with-sni-tls")
        task_ip = Task(
            {"type": TaskType.IP},
            payload={TaskType.IP: host},
        )
        task_domain = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-nginx-with-sni-tls"},
        )
        self.run_task(task_ip)
        self.run_task(task_domain)
        call_ip, call_domain = self.mock_db.save_task_result.call_args_list
        self.assertEqual(
            call_ip.kwargs["status_reason"], "Found ports: 443 (service: http ssl: False, version: nginx/1.29.0)"
        )
        self.assertEqual(
            call_domain.kwargs["status_reason"], "Found ports: 443 (service: http ssl: True, version: nginx/1.29.0)"
        )
