import unittest
from urllib.parse import urlparse

from artemis.reporting.base.normal_form import get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType


class TestReportIPv6(unittest.TestCase):
    def test_normalizes_ipv6_http_urls(self) -> None:
        for url in ("http://[2001:db8::1]/path?q=1", "https://[2001:db8::1]:443/path?q=1"):
            with self.subTest(url=url):
                self.assertEqual(get_url_normal_form(url), "http_or_https://[2001:db8::1]:0/path?q=1")

    def test_preserves_nonstandard_port(self) -> None:
        self.assertEqual(get_url_normal_form("https://[::1]:12345/path"), "https://[::1]:12345/path")

    def test_domain_and_ipv4_normalization_unchanged(self) -> None:
        self.assertEqual(get_url_normal_form("https://www.example.org/path"), "http_or_https://example.org:0/path")
        self.assertEqual(get_url_normal_form("http://192.0.2.1/path"), "http_or_https://192.0.2.1:0/path")

    def test_alternative_ip_url_remains_parseable(self) -> None:
        for address in ("2001:db8::1", "192.0.2.1"):
            for port in ("", ":12345"):
                with self.subTest(address=address, port=port):
                    original = Report(
                        top_level_target="example.org",
                        target=f"https://example.org{port}/path?q=1",
                        report_type=ReportType("test"),
                        target_ip=address,
                        target_ip_checked=True,
                    )
                    alternative = original.alternative_with_ip_address()
                    self.assertIsNotNone(alternative)
                    assert alternative is not None
                    parsed = urlparse(alternative.target)
                    self.assertEqual(parsed.hostname, address)
                    self.assertEqual(parsed.port, 12345 if port else None)
                    self.assertEqual(parsed.path, "/path")
                    self.assertEqual(parsed.query, "q=1")
                    self.assertEqual(original.target, f"https://example.org{port}/path?q=1")
