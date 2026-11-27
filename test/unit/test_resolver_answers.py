import unittest

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from artemis.resolvers import _results_from_answer


class TestResolverAnswers(unittest.TestCase):
    def test_cname_results(self) -> None:
        addresses = ("192.0.2.1", "192.0.2.2")
        nameservers = ("ns1.example.", "ns2.example.")
        cases = (
            ("A", (("A", addresses),), set(addresses)),
            ("NS", (("NS", nameservers),), {"ns1.example", "ns2.example"}),
            ("A", (("NS", nameservers),), set()),
            ("NS", (("A", addresses),), set()),
            ("A", (("NS", nameservers), ("A", addresses)), set(addresses)),
            ("NS", (("A", addresses), ("NS", nameservers)), {"ns1.example", "ns2.example"}),
        )
        for query_type, records, expected in cases:
            for nested in (False, True):
                with self.subTest(query_type=query_type, records=records, nested=nested):
                    query = dns.message.make_query("alias.example.", query_type)
                    response = dns.message.make_response(query)
                    assert isinstance(response, dns.message.QueryMessage)
                    target = "intermediate.example." if nested else "target.example."
                    response.answer.append(dns.rrset.from_text("alias.example.", 60, "IN", "CNAME", target))
                    if nested:
                        response.answer.append(dns.rrset.from_text(target, 60, "IN", "CNAME", "target.example."))
                    for record_type, values in records:
                        response.answer.append(dns.rrset.from_text("target.example.", 60, "IN", record_type, *values))
                    response = dns.message.from_wire(response.to_wire())
                    answer = dns.resolver.Answer(
                        query.question[0].name, dns.rdatatype.from_text(query_type), dns.rdataclass.IN, response
                    )
                    self.assertEqual(
                        _results_from_answer("alias.example", answer, dns.rdatatype.from_text(query_type)), expected
                    )
