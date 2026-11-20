from socket import gethostbyname
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
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

    def test_ldap_is_fingerprinted_by_protocol_and_risky_ports_do_not_spawn_tasks(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-openldap"},
        )
        with patch("artemis.modules.port_scanner.PORTS", [389, 636]):
            results = self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        (ports,) = call.kwargs["data"].values()
        self.assertEqual(ports["389"]["service"], "ldap")
        self.assertEqual(ports["636"]["service"], "ldap")
        self.assertTrue(ports["636"]["ssl"])

        # 636 is a risky port - reported but no task spawned by default; 389 is a standard port with a task
        spawned_ports = [result.payload["port"] for result in results]
        self.assertIn(389, spawned_ports)
        self.assertNotIn(636, spawned_ports)
        self.assertEqual(len(spawned_ports), 1)

    def test_risky_ports_spawn_tasks_when_enabled(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "test-openldap"},
        )
        with (
            patch("artemis.modules.port_scanner.PORTS", [389, 636]),
            patch.object(Config.Modules.PortScanner, "PORT_SCANNER_SPAWN_TASKS_FOR_RISKY_PORTS", True),
        ):
            results = self.run_task(task)
        spawned_ports = sorted(result.payload["port"] for result in results)
        self.assertIn(636, spawned_ports)
        self.assertEqual(spawned_ports, [389, 636])
