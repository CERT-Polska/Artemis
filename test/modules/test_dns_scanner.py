from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.resolver
import dns.xfr
import dns.zone
from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.dns_scanner import DnsScanner


class DnsScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = DnsScanner  # type: ignore

    def test_known_bad_nameserver(self) -> None:
        """
        Test that the module detects known bad nameservers.
        """
        task = Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: "example.com"})

        # Mock DNS responses
        with patch("dns.resolver.resolve") as mock_resolve:
            # Mock SOA and NS responses
            mock_resolve.side_effect = [
                [MagicMock(mname="fns1.42.pl")],  # SOA response
                [MagicMock(to_text=lambda: "fns1.42.pl")],  # NS response
            ]

            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertIn("fns1.42.pl in known bad nameservers", call.kwargs["status_reason"])

    def test_nonexistent_nameserver(self) -> None:
        """
        Test that the module detects nonexistent nameservers.
        """
        task = Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: "example.com"})

        # Mock DNS responses
        with patch("dns.resolver.resolve") as mock_resolve:
            # Mock SOA and NS responses
            mock_resolve.side_effect = [
                [MagicMock(mname="nonexistent.ns")],  # SOA response
                dns.resolver.NXDOMAIN("nonexistent.ns"),  # type: ignore # Simulate nonexistent nameserver
            ]

            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertIn("nonexistent.ns domain does not exist", call.kwargs["status_reason"])

    def test_zone_transfer_vulnerability(self) -> None:
        """
        Test that the module detects DNS zone transfer vulnerabilities.
        """
        task = Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: "example.com"})

        # Mock DNS responses
        with patch("dns.resolver.resolve") as mock_resolve, patch("dns.query.xfr") as mock_xfr:
            # Mock SOA and NS responses
            mock_resolve.side_effect = [
                [MagicMock(mname="ns1.example.com")],  # SOA response
                [MagicMock(to_text=lambda: "ns1.example.com")],  # NS response
            ]

            # Mock zone transfer response
            mock_zone = MagicMock()
            mock_zone.nodes = {"node1": "data1", "node2": "data2"}
            mock_xfr.return_value = mock_zone

            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertIn("DNS zone transfer is possible", call.kwargs["status_reason"])
            self.assertEqual(call.kwargs["data"]["zone_size"], 2)

    def test_no_issues_found(self) -> None:
        """
        Test that the module returns OK status when no issues are found.
        """
        task = Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: "example.com"})

        # Mock DNS responses
        with patch("dns.resolver.resolve") as mock_resolve:
            # Mock SOA and NS responses
            mock_resolve.side_effect = [
                [MagicMock(mname="ns1.example.com")],  # SOA response
                [MagicMock(to_text=lambda: "ns1.example.com")],  # NS response
            ]

            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.OK)
            self.assertIsNone(call.kwargs["status_reason"])
