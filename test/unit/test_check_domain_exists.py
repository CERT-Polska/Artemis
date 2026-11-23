import socket
import unittest
from typing import Callable, Dict, List
from unittest.mock import MagicMock, patch

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
from karton.core.test import ConfigMock

from artemis.binds import TaskType
from artemis.module_base import ArtemisBase
from artemis.resolvers import lookup


class _MinimalModule(ArtemisBase):
    identity = "check-domain-exists-test-module"
    filters = [{"type": TaskType.DOMAIN.value}]


def _answer(domain: str, query_type: str, records: List[dns.rrset.RRset]) -> dns.resolver.Answer:
    query = dns.message.make_query(domain, query_type)
    response = dns.message.make_response(query)
    response.answer.extend(records)
    # Go through the wire format, as for a real server response, so that dnspython indexes the
    # records and follows the CNAME chain the way it does in production.
    parsed = dns.message.from_wire(response.to_wire())
    assert isinstance(parsed, dns.message.QueryMessage)
    return dns.resolver.Answer(query.question[0].name, dns.rdatatype.from_text(query_type), dns.rdataclass.IN, parsed)


def _fake_resolve(records: Dict[str, List[dns.rrset.RRset]]) -> Callable[..., dns.resolver.Answer]:
    def resolve(domain: str, query_type: str) -> dns.resolver.Answer:
        if query_type not in records:
            raise dns.resolver.NoAnswer
        return _answer(domain, query_type, records[query_type])

    return resolve


class CheckDomainExistsTest(unittest.TestCase):
    module: _MinimalModule

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _MinimalModule(config=ConfigMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def setUp(self) -> None:
        lookup.cache_clear()
        self.addCleanup(lookup.cache_clear)
        # The name is not in the hosts file, so the lookup goes to DNS.
        self.enterContext(patch("artemis.resolvers.socket.gethostbyname", side_effect=socket.gaierror))

    def _exists(self, records: Dict[str, List[dns.rrset.RRset]]) -> bool:
        with patch("artemis.resolvers.dns.resolver.resolve", side_effect=_fake_resolve(records)):
            return self.module.check_domain_exists("example.test")

    def test_domain_with_only_mx_records_exists(self) -> None:
        mx = dns.rrset.from_text("example.test.", 60, "IN", "MX", "10 mail.example.org.")
        self.assertTrue(self._exists({"MX": [mx]}))

    def test_domain_with_only_aaaa_records_exists(self) -> None:
        aaaa = dns.rrset.from_text("example.test.", 60, "IN", "AAAA", "2001:db8::1")
        self.assertTrue(self._exists({"AAAA": [aaaa]}))

    def test_domain_with_aaaa_records_behind_cname_exists(self) -> None:
        cname = dns.rrset.from_text("example.test.", 60, "IN", "CNAME", "v6.example.org.")
        aaaa = dns.rrset.from_text("v6.example.org.", 60, "IN", "AAAA", "2001:db8::2")
        self.assertTrue(self._exists({"AAAA": [cname, aaaa]}))

    def test_domain_with_a_records_exists(self) -> None:
        a = dns.rrset.from_text("example.test.", 60, "IN", "A", "192.0.2.1")
        self.assertTrue(self._exists({"A": [a]}))

    def test_domain_without_a_aaaa_or_mx_records_does_not_exist(self) -> None:
        self.assertFalse(self._exists({}))

    def test_mx_lookup_returns_mail_server_names(self) -> None:
        mx = dns.rrset.from_text("example.test.", 60, "IN", "MX", "10 mail.example.org.", "20 backup.example.org.")
        with patch("artemis.resolvers.dns.resolver.resolve", side_effect=_fake_resolve({"MX": [mx]})):
            self.assertEqual(lookup("example.test", "MX"), {"mail.example.org", "backup.example.org"})

    def test_aaaa_lookup_returns_ipv6_addresses(self) -> None:
        aaaa = dns.rrset.from_text("example.test.", 60, "IN", "AAAA", "2001:db8::1", "2001:db8::2")
        with patch("artemis.resolvers.dns.resolver.resolve", side_effect=_fake_resolve({"AAAA": [aaaa]})):
            self.assertEqual(lookup("example.test", "AAAA"), {"2001:db8::1", "2001:db8::2"})


if __name__ == "__main__":
    unittest.main()
