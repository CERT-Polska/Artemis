import unittest
from typing import List

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from artemis.resolvers import _results_from_answer


class TestDNSAnswerNames(unittest.TestCase):
    def make_answer(self, domain: str, records: List[dns.rrset.RRset]) -> dns.resolver.Answer:
        query = dns.message.make_query(domain, "NS")
        response = dns.message.make_response(query)
        assert isinstance(response, dns.message.QueryMessage)
        response.answer.extend(records)
        return dns.resolver.Answer(dns.name.from_text(domain), dns.rdatatype.NS, dns.rdataclass.IN, response)

    def test_matches_absolute_and_mixed_case_owner_names(self) -> None:
        records = [dns.rrset.from_text("ExAmPlE.test.", 60, "IN", "NS", "ns1.example.test.")]
        for domain in ("example.test", "example.test.", "EXAMPLE.TEST."):
            with self.subTest(domain=domain):
                answer = self.make_answer(domain, records)
                self.assertEqual(_results_from_answer(domain, answer, dns.rdatatype.NS), {"ns1.example.test"})

    def test_matches_mixed_case_cname_targets(self) -> None:
        records = [
            dns.rrset.from_text("example.test.", 60, "IN", "CNAME", "Alias.Example.test."),
            dns.rrset.from_text("alias.example.test.", 60, "IN", "CNAME", "Final.Example.test."),
            dns.rrset.from_text("final.example.test.", 60, "IN", "NS", "ns1.example.test.", "ns2.example.test."),
        ]
        answer = self.make_answer("example.test", records)
        self.assertEqual(
            _results_from_answer("example.test", answer, dns.rdatatype.NS),
            {"ns1.example.test", "ns2.example.test"},
        )

    def test_ignores_unrelated_owner(self) -> None:
        records = [dns.rrset.from_text("other.test.", 60, "IN", "NS", "ns1.other.test.")]
        answer = self.make_answer("example.test", records)
        self.assertEqual(_results_from_answer("example.test", answer, dns.rdatatype.NS), set())
