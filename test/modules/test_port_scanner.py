from socket import gethostbyname
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

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
        """Full pipeline (naabu → fingerprintx → result) detects HTTP on test-nginx."""
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

    def test_fingerprintx_fails_fallback_detects_http(self) -> None:
        """fingerprintx failure → retry exhaustion → HTTP fallback → successful detection.

        Uses test-nginx (a real HTTP service) with fingerprintx patched to
        always return empty output. This forces the fallback path while keeping
        naabu port discovery and HTTP probing fully real.

        Validates the complete flow:
        - naabu detects port 80 as open
        - fingerprintx retries 3 times and "fails" (mocked to return b"")
        - HTTP fallback makes a real HEAD request to nginx and succeeds
        - port 80 is reported as service=http
        """
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-nginx"},
        )
        with patch("artemis.modules.port_scanner.check_output_log_on_error", return_value=b""):
            with self.assertLogs("port_scanner", level="INFO") as log_cm:
                self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        port_data = list(call.kwargs["data"].values())[0]
        self.assertIn("80", port_data)
        self.assertEqual(port_data["80"]["service"], "http")
        self.assertFalse(port_data["80"]["ssl"])

        # Verify retries were exhausted and fallback was triggered
        fallback_msgs = [m for m in log_cm.output if "attempting HTTP fallback" in m]
        self.assertTrue(fallback_msgs, "Expected fingerprintx retries to exhaust and trigger HTTP fallback")
        self.assertIn("after 3 attempts", fallback_msgs[0])

        # Verify fallback succeeded (no "skipping port" message)
        success_msgs = [m for m in log_cm.output if "HTTP fallback succeeded" in m]
        self.assertTrue(success_msgs, "Expected HTTP fallback to successfully detect the service")
        skip_msgs = [m for m in log_cm.output if "skipping port" in m]
        self.assertFalse(skip_msgs, "Port should not be skipped when fallback succeeds")

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
