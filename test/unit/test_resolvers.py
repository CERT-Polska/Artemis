import socket
import unittest
from unittest.mock import patch

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from artemis.resolvers import lookup


class TestResolvers(unittest.TestCase):
    def setUp(self) -> None:
        lookup.cache_clear()
        self.addCleanup(lookup.cache_clear)
        self.host_lookup = self.enterContext(
            patch("artemis.resolvers.socket.gethostbyname", side_effect=socket.gaierror)
        )
        self.dns_lookup = self.enterContext(
            patch("artemis.resolvers.dns.resolver.resolve", side_effect=AssertionError("Unexpected DNS query"))
        )

    @staticmethod
    def answer(domain: str, query_type: str, *values: str) -> dns.resolver.Answer:
        query = dns.message.make_query(domain, query_type)
        response = dns.message.make_response(query)
        assert isinstance(response, dns.message.QueryMessage)
        response.answer.append(dns.rrset.from_text(domain, 60, "IN", query_type, *values))
        return dns.resolver.Answer(
            query.question[0].name, dns.rdatatype.from_text(query_type), dns.rdataclass.IN, response
        )

    def test_host_lookup(self) -> None:
        self.host_lookup.side_effect = None
        self.host_lookup.return_value = "192.0.2.1"

        self.assertEqual(lookup("host.example"), {"192.0.2.1"})

        self.host_lookup.assert_called_once_with("host.example")
        self.dns_lookup.assert_not_called()

    def test_dns_fallback(self) -> None:
        self.dns_lookup.side_effect = None
        self.dns_lookup.return_value = self.answer("host.example", "A", "192.0.2.1", "192.0.2.2")

        self.assertEqual(lookup("HOST.EXAMPLE"), {"192.0.2.1", "192.0.2.2"})

        self.host_lookup.assert_called_once_with("HOST.EXAMPLE")
        self.dns_lookup.assert_called_once_with("host.example", "A")

    def test_nameserver_lookup(self) -> None:
        self.dns_lookup.side_effect = None
        self.dns_lookup.return_value = self.answer("host.example", "NS", "ns1.example.", "ns2.example.")

        self.assertEqual(lookup("host.example", "NS"), {"ns1.example", "ns2.example"})

        self.host_lookup.assert_not_called()
        self.dns_lookup.assert_called_once_with("host.example", "NS")

    def test_missing_dns_records(self) -> None:
        for error in (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            with self.subTest(error=error):
                lookup.cache_clear()
                self.dns_lookup.side_effect = error

                self.assertEqual(lookup("missing.example"), set())
