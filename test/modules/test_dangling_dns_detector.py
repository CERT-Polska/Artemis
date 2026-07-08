from test.base import ArtemisModuleTestCase
from typing import Any
from unittest.mock import MagicMock, patch

import dns.name
from dns import rdatatype

from artemis.modules.dangling_dns_detector import DanglingDnsDetector


class TestDanglingDnsDetector(ArtemisModuleTestCase):
    karton_class = DanglingDnsDetector  # type: ignore

    @patch("artemis.modules.dangling_dns_detector.direct_dns_query")
    @patch("artemis.modules.dangling_dns_detector.dns_query")
    @patch("dns.resolver.resolve")
    def test_check_ns_dangling(self, mock_resolve, mock_dns_query, mock_direct_dns_query) -> None:  # type: ignore
        # given
        ns_record = MagicMock()
        ns_record.rdtype = rdatatype.NS
        ns_record.target.to_text.return_value = "ns1.unregistered.example.com."
        mock_ns_answer = MagicMock()
        mock_ns_answer.rrset = [ns_record]
        mock_ns_answer.qname = dns.name.from_text("dangling.example.com.")
        mock_ns_answer.__iter__.return_value = iter([ns_record])
        mock_resolve.side_effect = [mock_ns_answer]
        # dns_query returns None for both A and AAAA
        mock_dns_query.side_effect = [None, None]

        # when
        result: list[dict[str, Any]] = []
        self.karton.check_ns("dangling.example.com", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.NS)
        self.assertTrue("dangling NS" in result[0]["message"])

    @patch("artemis.modules.dangling_dns_detector.direct_dns_query")
    @patch("artemis.modules.dangling_dns_detector.dns_query")
    @patch("dns.resolver.resolve")
    def test_check_ns_valid(self, mock_resolve, mock_dns_query, mock_direct_dns_query) -> None:  # type: ignore
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
        a_record.address = "8.8.8.8"
        mock_a_answer = MagicMock()
        mock_a_answer.__iter__.return_value = iter([a_record])
        mock_dns_query.side_effect = [mock_a_answer, None]

        # direct_dns_query returns a reply with SOA
        mock_reply = MagicMock()
        mock_reply.answer = [MagicMock(rdtype=rdatatype.SOA, name=dns.name.from_text("valid.example.com."))]
        mock_direct_dns_query.return_value = mock_reply

        # when
        result: list[dict[str, Any]] = []
        self.karton.check_ns("valid.example.com", result)

        # then
        self.assertFalse(result)

    @patch("dns.resolver.resolve")
    def test_check_cname_dangling(self, mock_resolve) -> None:  # type: ignore
        # given
        cname_record = MagicMock()
        cname_record.rdtype = rdatatype.CNAME
        cname_record.target.to_text.return_value = "unregistered.example.com."
        mock_answer = MagicMock()
        mock_answer.rrset = [cname_record]
        mock_answer.__iter__.return_value = iter([cname_record])
        mock_resolve.side_effect = [mock_answer]

        # when
        result: list[dict[str, Any]] = []
        self.karton.check_cname("dangling.example.com", result)

        # then
        self.assertTrue(len(result) == 1)
        self.assertTrue(result[0]["record"] == rdatatype.CNAME)
        self.assertTrue("does not resolve" in result[0]["message"])

    @patch("artemis.modules.dangling_dns_detector.dns_query")
    @patch("dns.resolver.resolve")
    def test_check_cname_registered(self, mock_resolve, mock_dns_query) -> None:  # type: ignore
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
        mock_dns_query.side_effect = [mock_a_answer, None, None]

        # when
        result: list[dict[str, Any]] = []
        self.karton.check_cname("registered.example.com", result)

        # then
        self.assertFalse(result)

    @patch("dns.resolver.resolve")
    def test_check_cname_no_cname(self, mock_resolve) -> None:  # type: ignore
        # given
        mock_answer = MagicMock()
        mock_answer.rrset = None
        mock_answer.__iter__.return_value = iter([])
        mock_resolve.return_value = mock_answer

        # when
        result: list[dict[str, Any]] = []
        self.karton.check_cname("nocname.example.com", result)

        # then
        self.assertFalse(result)
