import unittest
from typing import Dict, List
from unittest.mock import MagicMock, patch

import dns.name
from dns import rdatatype

from artemis.modules.dangling_dns_detector import DanglingDnsDetector


class TestDanglingDnsDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DanglingDnsDetector()

    @patch("artemis.modules.dangling_dns_detector.direct_dns_query")
    @patch("artemis.modules.dangling_dns_detector.edns_query")
    @patch("dns.resolver.resolve")
    def test_check_ns_dangling(self, mock_resolve, mock_edns_query, mock_direct_dns_query) -> None:
        # given
        ns_record = MagicMock()
        ns_record.rdtype = rdatatype.NS
        ns_record.target.to_text.return_value = "ns1.unregistered.example.com."
        mock_ns_answer = MagicMock()
        mock_ns_answer.rrset = [ns_record]
        mock_ns_answer.qname = dns.name.from_text("dangling.example.com.")
        mock_ns_answer.__iter__.return_value = iter([ns_record])
        mock_resolve.side_effect = [mock_ns_answer]
        # edns_query returns None for both A and AAAA
        mock_edns_query.side_effect = [None, None]

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_ns("dangling.example.com", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.NS)
        self.assertTrue("dangling NS" in result[0]["message"])

    @patch("artemis.modules.dangling_dns_detector.direct_dns_query")
    @patch("artemis.modules.dangling_dns_detector.edns_query")
    @patch("dns.resolver.resolve")
    def test_check_ns_valid(self, mock_resolve, mock_edns_query, mock_direct_dns_query) -> None:
        # given
        ns_record = MagicMock()
        ns_record.rdtype = rdatatype.NS
        ns_record.target.to_text.return_value = "ns1.valid.example.com."
        mock_ns_answer = MagicMock()
        mock_ns_answer.rrset = [ns_record]
        mock_ns_answer.qname = dns.name.from_text("valid.example.com.")
        mock_ns_answer.__iter__.return_value = iter([ns_record])
        mock_resolve.side_effect = [mock_ns_answer]

        a_record = MagicMock()
        a_record.rdtype = rdatatype.A
        a_record.address = "203.0.113.10"
        mock_a_answer = MagicMock()
        mock_a_answer.__iter__.return_value = iter([a_record])
        mock_edns_query.side_effect = [mock_a_answer, None]

        # direct_dns_query returns a reply with SOA
        mock_reply = MagicMock()
        mock_reply.answer = [MagicMock(rdtype=rdatatype.SOA, name=dns.name.from_text("valid.example.com."))]
        mock_direct_dns_query.return_value = mock_reply

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_ns("valid.example.com", result)

        # then
        self.assertFalse(result)

    @patch("artemis.modules.dangling_dns_detector.ip_exists")
    @patch("dns.resolver.resolve")
    def test_check_dns_ip_records_dangling_a(self, mock_resolve, mock_ip_exists) -> None:
        # given
        a_record = MagicMock()
        a_record.rdtype = rdatatype.A
        a_record.address = "203.0.113.1"
        mock_a_answer = MagicMock()
        mock_a_answer.rrset = [a_record]
        mock_a_answer.__iter__.return_value = iter([a_record])
        mock_aaaa_answer = MagicMock()
        mock_aaaa_answer.rrset = None
        mock_aaaa_answer.__iter__.return_value = iter([])
        mock_resolve.side_effect = [mock_a_answer, mock_aaaa_answer]
        mock_ip_exists.return_value = False

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_dns_ip_records("dangling.example.com", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.A)
        self.assertTrue("does not resolve" in result[0]["message"])

    @patch("artemis.modules.dangling_dns_detector.ip_exists")
    @patch("dns.resolver.resolve")
    def test_check_dns_ip_records_valid_a(self, mock_resolve, mock_ip_exists) -> None:
        # given
        a_record = MagicMock()
        a_record.rdtype = rdatatype.A
        a_record.address = "203.0.113.2"
        mock_a_answer = MagicMock()
        mock_a_answer.rrset = [a_record]
        mock_a_answer.__iter__.return_value = iter([a_record])
        mock_aaaa_answer = MagicMock()
        mock_aaaa_answer.rrset = None
        mock_aaaa_answer.__iter__.return_value = iter([])
        mock_resolve.side_effect = [mock_a_answer, mock_aaaa_answer]
        mock_ip_exists.return_value = True

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_dns_ip_records("valid.example.com", result)

        # then
        self.assertFalse(result)

    @patch("artemis.modules.dangling_dns_detector.ip_exists")
    @patch("dns.resolver.resolve")
    def test_check_dns_ip_records_dangling_aaaa(self, mock_resolve, mock_ip_exists) -> None:
        # given
        aaaa_record = MagicMock()
        aaaa_record.rdtype = rdatatype.AAAA
        aaaa_record.address = "2001:db8::1"
        mock_a_answer = MagicMock()
        mock_a_answer.rrset = None
        mock_a_answer.__iter__.return_value = iter([])
        mock_aaaa_answer = MagicMock()
        mock_aaaa_answer.rrset = [aaaa_record]
        mock_aaaa_answer.__iter__.return_value = iter([aaaa_record])
        mock_resolve.side_effect = [mock_a_answer, mock_aaaa_answer]
        mock_ip_exists.return_value = False

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_dns_ip_records("dangling.example.com", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.AAAA)
        self.assertTrue("does not resolve" in result[0]["message"])

    @patch("artemis.modules.dangling_dns_detector.ip_exists")
    @patch("dns.resolver.resolve")
    def test_check_dns_ip_records_no_records(self, mock_resolve, mock_ip_exists) -> None:
        # given
        mock_a_answer = MagicMock()
        mock_a_answer.rrset = None
        mock_a_answer.__iter__.return_value = iter([])
        mock_aaaa_answer = MagicMock()
        mock_aaaa_answer.rrset = None
        mock_aaaa_answer.__iter__.return_value = iter([])
        mock_resolve.side_effect = [mock_a_answer, mock_aaaa_answer]

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_dns_ip_records("norecords.example.com", result)

        # then
        self.assertFalse(result)

    @patch("dns.resolver.resolve")
    def test_check_cname_dangling(self, mock_resolve) -> None:
        # given
        cname_record = MagicMock()
        cname_record.rdtype = rdatatype.CNAME
        cname_record.target.to_text.return_value = "unregistered.example.com."
        mock_answer = MagicMock()
        mock_answer.rrset = [cname_record]
        mock_answer.__iter__.return_value = iter([cname_record])
        mock_resolve.side_effect = [mock_answer]

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_cname("dangling.example.com", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.CNAME)
        self.assertTrue("does not resolve" in result[0]["message"])

    @patch("artemis.modules.dangling_dns_detector.edns_query")
    @patch("dns.resolver.resolve")
    def test_check_cname_registered(self, mock_resolve, mock_edns_query) -> None:
        # given
        cname_record = MagicMock()
        cname_record.rdtype = rdatatype.CNAME
        cname_record.target.to_text.return_value = "registered.example.com."
        mock_cname_answer = MagicMock()
        mock_cname_answer.rrset = [cname_record]
        mock_cname_answer.__iter__.return_value = iter([cname_record])
        mock_resolve.side_effect = [mock_cname_answer]

        a_record = MagicMock()
        a_record.rdtype = rdatatype.A
        mock_a_answer = MagicMock()
        mock_a_answer.__iter__.return_value = iter([a_record])
        mock_edns_query.side_effect = [mock_a_answer, None, None]

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_cname("registered.example.com", result)

        # then
        self.assertFalse(result)

    @patch("dns.resolver.resolve")
    def test_check_cname_no_cname(self, mock_resolve) -> None:
        # given
        mock_answer = MagicMock()
        mock_answer.rrset = None
        mock_answer.__iter__.return_value = iter([])
        mock_resolve.return_value = mock_answer

        # when
        result: List[Dict[str, str]] = []
        self.detector.check_cname("nocname.example.com", result)

        # then
        self.assertFalse(result)


class TestDanglingDnsDetectorIntegration(unittest.TestCase):
    def setUp(self):
        self.detector = DanglingDnsDetector()

    def test_cname_dangling_real_domain(self) -> None:
        # when
        result: List[Dict[str, str]] = []
        self.detector.check_cname("bad.kadetest.xyz", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.CNAME)
        self.assertTrue("does not resolve" in result[0]["message"])

    def test_check_dns_ip_records_integration(self) -> None:
        # when
        result: List[Dict[str, str]] = []
        self.detector.check_dns_ip_records("dangling.test.artemis.lab.cert.pl", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.A)
        self.assertTrue("does not resolve" in result[0]["message"])


if __name__ == "__main__":
    unittest.main()
