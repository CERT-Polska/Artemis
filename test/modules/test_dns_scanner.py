"""Test module for DNS scanner functionality."""
from unittest.mock import patch, MagicMock
import dns.resolver
import dns.rcode
import dns.message
from dns.resolver import NXDOMAIN, Answer
from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from test.base import ArtemisModuleTestCase
from artemis.modules.dns_scanner import DnsScanner


class DnsScannerTest(ArtemisModuleTestCase):
    """Test cases for DNS scanner module."""
    
    karton_class = DnsScanner  # type: ignore

    def setUp(self):
        """Test case setup."""
        super().setUp()
        
        # Setup common test data
        self.domain = "example.com"
        self.good_nameserver = "ns.example.com."
        self.bad_nameserver = "fns1.42.pl."
        self.valid_ip = "192.168.0.1"
        self.out_of_range_ip = "192.0.2.1"
        
        # Create a mock QueryMessage for successful responses
        self.good_response = dns.message.make_query(self.domain, 'A')
        self.good_response.set_rcode(dns.rcode.NOERROR)

    def _create_mock_answer(self, value):
        """Create a mock DNS answer with proper typing.
        
        Args:
            value: Can be:
                - tuple: For SOA records (zone_name, mname)
                - str: For NS records
                - dict: For A records {'address': ip}
                - Exception: For error cases
        """
        mock_answer = MagicMock(spec=Answer)
        
        if isinstance(value, tuple):  # For SOA records
            zone_name, mname = value
            mock_answer.rrset = MagicMock(
                name=MagicMock(to_text=lambda: zone_name),
                items=[MagicMock(mname=MagicMock(to_text=lambda: mname))]
            )
        elif isinstance(value, str):  # For NS records
            mock_answer.rrset = MagicMock(
                items=[MagicMock(to_text=lambda: value)]
            )
        elif isinstance(value, dict):  # For A records
            mock_answer.rrset = MagicMock(
                items=[MagicMock(address=value.get('address'))]
            )
        elif isinstance(value, Exception):  # For error cases
            raise value
            
        return mock_answer

    def test_zone_transfer(self):
        """Should detect when DNS zone transfer is possible."""
        task = Task({"type": TaskType.DOMAIN}, payload={"domain": self.domain})

        with patch("dns.resolver.zone_for_name") as mock_zone_for_name, \
             patch("dns.resolver.Resolver") as mock_resolver, \
             patch("dns.query.udp") as mock_udp, \
             patch("dns.query.xfr") as mock_xfr, \
             patch("dns.zone.from_xfr") as mock_from_xfr:

            # Mock zone_for_name to return our domain immediately
            mock_zone_for_name.return_value = dns.name.from_text(self.domain)
            
            # Setup mock resolver responses
            mock_resolver.return_value.resolve.side_effect = [
                # SOA query for mname
                self._create_mock_answer((self.domain, self.good_nameserver)),
                # NS query (list of nameservers)
                self._create_mock_answer([self.good_nameserver]),
                # A record for nameserver
                self._create_mock_answer({"address": self.valid_ip})
            ]
            
            # Mock DNS query response
            mock_udp.return_value = self.good_response
            
            # Mock successful zone transfer
            mock_xfr.return_value = iter([b"zone data"])
            mock_from_xfr.return_value = MagicMock(nodes={self.domain: None})

            self.run_task(task)
            result = self.mock_db.save_task_result.call_args[1]

            self.assertEqual(result["status"], TaskStatus.INTERESTING)
            self.assertIn("DNS zone transfer is possible", result["status_reason"])
            self.assertEqual(
                result["data"]["topmost_transferable_zone_name"],
                self.domain
            )

    def test_known_bad_nameserver(self):
        """Should flag known bad nameservers."""
        task = Task({"type": TaskType.DOMAIN}, payload={"domain": self.domain})

        with patch("dns.resolver.zone_for_name") as mock_zone_for_name, \
             patch("dns.resolver.Resolver") as mock_resolver, \
             patch("dns.query.udp") as mock_udp:

            mock_zone_for_name.return_value = dns.name.from_text(self.domain)
            
            mock_resolver.return_value.resolve.side_effect = [
                self._create_mock_answer((self.domain, self.good_nameserver)),
                self._create_mock_answer([self.bad_nameserver, self.good_nameserver]),
                self._create_mock_answer({"address": self.valid_ip}),
                self._create_mock_answer({"address": "192.0.2.1"})
            ]
            
            mock_udp.return_value = self.good_response

            self.run_task(task)
            result = self.mock_db.save_task_result.call_args[1]

            self.assertEqual(result["status"], TaskStatus.INTERESTING)
            self.assertIn(
                f"{self.bad_nameserver} in known bad nameservers",
                result["status_reason"]
            )
            self.assertIn("nameservers", result["data"])

    def test_nameserver_nxdomain(self):
        """Should handle nameservers that don't resolve."""
        task = Task({"type": TaskType.DOMAIN}, payload={"domain": self.domain})

        with patch("dns.resolver.zone_for_name") as mock_zone_for_name, \
             patch("dns.resolver.Resolver") as mock_resolver:

            mock_zone_for_name.return_value = dns.name.from_text(self.domain)
            
            mock_resolver.return_value.resolve.side_effect = [
                self._create_mock_answer((self.domain, self.good_nameserver)),
                self._create_mock_answer([self.good_nameserver]),
                NXDOMAIN(qnames=["nonexistent.example.com"])
            ]

            self.run_task(task)
            result = self.mock_db.save_task_result.call_args[1]

            self.assertEqual(result["status"], TaskStatus.INTERESTING)
            self.assertTrue(result["data"].get("ns_does_not_exist"))
            self.assertIn("domain does not exist", result["status_reason"])

    def test_nameserver_not_know_domain(self):
        """Should detect when nameserver doesn't know the domain."""
        task = Task({"type": TaskType.DOMAIN}, payload={"domain": self.domain})

        with patch("dns.resolver.zone_for_name") as mock_zone_for_name, \
             patch("dns.resolver.Resolver") as mock_resolver, \
             patch("dns.query.udp") as mock_udp:

            mock_zone_for_name.return_value = dns.name.from_text(self.domain)
            
            mock_resolver.return_value.resolve.side_effect = [
                self._create_mock_answer((self.domain, self.good_nameserver)),
                self._create_mock_answer([self.good_nameserver]),
                self._create_mock_answer({"address": self.valid_ip})
            ]
            
            # Mock NXDOMAIN response for domain
            nxdomain_response = dns.message.make_query(self.domain, 'A')
            nxdomain_response.set_rcode(dns.rcode.NXDOMAIN)
            mock_udp.return_value = nxdomain_response

            self.run_task(task)
            result = self.mock_db.save_task_result.call_args[1]

            self.assertEqual(result["status"], TaskStatus.INTERESTING)
            self.assertTrue(result["data"].get("ns_not_knowing_domain"))

    def test_nameserver_outside_ip_range(self):
        """Should skip nameservers outside specified IP range."""
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={"domain": self.domain, "ip_range": "192.168.0.0/24"}
        )

        with patch("dns.resolver.zone_for_name") as mock_zone_for_name, \
             patch("dns.resolver.Resolver") as mock_resolver, \
             patch("dns.query.udp") as mock_udp:

            mock_zone_for_name.return_value = dns.name.from_text(self.domain)
            
            mock_resolver.return_value.resolve.side_effect = [
                self._create_mock_answer((self.domain, self.good_nameserver)),
                self._create_mock_answer([self.good_nameserver]),
                self._create_mock_answer({"address": self.out_of_range_ip})
            ]
            
            mock_udp.return_value = self.good_response

            self.run_task(task)
            result = self.mock_db.save_task_result.call_args[1]

            self.assertEqual(result["status"], TaskStatus.OK)
            self.assertIn(
                self.out_of_range_ip,
                result["data"]["nameservers_skipped_outside_ip_range"]
            )

    def test_all_ok(self):
        """Should return OK status when no issues found."""
        task = Task({"type": TaskType.DOMAIN}, payload={"domain": self.domain})

        with patch("dns.resolver.zone_for_name") as mock_zone_for_name, \
             patch("dns.resolver.Resolver") as mock_resolver, \
             patch("dns.query.udp") as mock_udp:

            mock_zone_for_name.return_value = dns.name.from_text(self.domain)
            
            mock_resolver.return_value.resolve.side_effect = [
                self._create_mock_answer((self.domain, self.good_nameserver)),
                self._create_mock_answer([self.good_nameserver]),
                self._create_mock_answer({"address": self.valid_ip})
            ]
            
            mock_udp.return_value = self.good_response

            self.run_task(task)
            result = self.mock_db.save_task_result.call_args[1]

            self.assertEqual(result["status"], TaskStatus.OK)
            self.assertIn("nameservers", result["data"])