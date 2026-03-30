from socket import gethostbyname
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

import requests
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

    @patch("artemis.modules.port_scanner.Config.Modules.PortScanner.ADD_PORTS_FROM_SHODAN_INTERNETDB", True)
    def test_shodan_internetdb_adds_ports(self) -> None:
        """Integration test that verifies Shodan InternetDB ports are persisted for a real IP."""
        test_ip = "8.8.8.8"
        with requests.get(f"https://internetdb.shodan.io/{test_ip}", timeout=5) as response:
            response.raise_for_status()
            internetdb_ports = {str(port) for port in response.json()["ports"]}

        with patch("artemis.modules.port_scanner.PORTS", [80]):
            task = Task(
                {"type": TaskType.IP},
                payload={TaskType.IP: test_ip},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        found_ports = set(call.kwargs["data"][test_ip].keys())
        shodan_only_ports = internetdb_ports - {"80"}
        self.assertTrue(len(shodan_only_ports) > 0)

        self.assertTrue(
            shodan_only_ports,
            f"Expected InternetDB to expose at least one non-80 port for {test_ip}, got: {sorted(internetdb_ports)}",
        )
        self.assertTrue(
            found_ports & shodan_only_ports,
            f"Expected Artemis to persist at least one Shodan-only port for {test_ip}. "
            f"InternetDB ports: {sorted(internetdb_ports)}, saved ports: {sorted(found_ports)}",
        )
