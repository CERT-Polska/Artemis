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

    def test_retry_and_fallback_both_fail_port_skipped(self) -> None:
        """End-to-end: unknown protocol triggers retry + fallback, port is skipped.

        test-tcp-raw is a real TCP server that speaks no known protocol.
        - naabu detects port 80 as open
        - fingerprintx retries 3 times, cannot identify the protocol
        - HTTP fallback tries HTTPS then HTTP, both fail (not an HTTP service)
        - port is correctly skipped — no results reported

        Log assertions verify each stage actually executes, guarding against
        vacuous passes (e.g. naabu not finding the port due to a race).
        """
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-tcp-raw"},
        )
        with self.assertLogs("port_scanner", level="INFO") as log_cm:
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertIsNone(call.kwargs["status_reason"])

        # Verify retries were exhausted and fallback was triggered
        fallback_msgs = [m for m in log_cm.output if "attempting HTTP fallback" in m]
        self.assertTrue(fallback_msgs, "Expected fingerprintx retries to exhaust and trigger HTTP fallback")
        self.assertIn("after 3 attempts", fallback_msgs[0])

        # Verify fallback failed and port was explicitly skipped
        skip_msgs = [m for m in log_cm.output if "skipping port" in m]
        self.assertTrue(skip_msgs, "Expected port to be skipped after fallback failure")

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
