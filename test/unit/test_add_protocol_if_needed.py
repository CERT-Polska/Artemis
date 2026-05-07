import unittest

from artemis.reporting.utils import add_protocol_if_needed


class TestAddProtocolIfNeeded(unittest.TestCase):
    def test_ipv4_host_port(self) -> None:
        self.assertEqual(add_protocol_if_needed("127.0.0.1:3306"), "mysql://127.0.0.1:3306")

    def test_ipv4_host_port_unknown_service(self) -> None:
        self.assertEqual(add_protocol_if_needed("127.0.0.1:65000"), "unknown://127.0.0.1:65000")

    def test_ipv6_host_port_does_not_crash(self) -> None:
        # Prior to the fix, split(":") on an IPv6 host:port raised ValueError.
        self.assertEqual(add_protocol_if_needed("::1:3306"), "mysql://::1:3306")
        self.assertEqual(
            add_protocol_if_needed("2001:db8::1:3306"),
            "mysql://2001:db8::1:3306",
        )

    def test_url_with_scheme_unchanged(self) -> None:
        self.assertEqual(add_protocol_if_needed("https://example.com"), "https://example.com")
        self.assertEqual(add_protocol_if_needed("mysql://127.0.0.1:3306"), "mysql://127.0.0.1:3306")

    def test_non_integer_port_returned_unchanged(self) -> None:
        self.assertEqual(add_protocol_if_needed("example.com:abc"), "example.com:abc")
        self.assertEqual(add_protocol_if_needed("host:"), "host:")

    def test_no_port_returned_unchanged(self) -> None:
        self.assertEqual(add_protocol_if_needed("example.com"), "example.com")

    def test_hostname_with_port(self) -> None:
        self.assertEqual(add_protocol_if_needed("example.com:80"), "http://example.com:80")
