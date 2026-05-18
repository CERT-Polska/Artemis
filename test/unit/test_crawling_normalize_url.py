import unittest

from artemis.crawling import _normalize_url


class TestNormalizeUrl(unittest.TestCase):
    """_normalize_url enforces a canonical form for URLs used as crawl-cache
    keys. Equivalent inputs (different case, default ports, surrounding
    whitespace, missing trailing slash) must map to the same canonical output."""

    def test_lowercases_host(self) -> None:
        self.assertEqual(_normalize_url("https://EXAMPLE.com/"), "https://example.com/")

    def test_strips_default_https_port(self) -> None:
        self.assertEqual(_normalize_url("https://example.com:443/"), "https://example.com/")

    def test_strips_default_http_port(self) -> None:
        self.assertEqual(_normalize_url("http://example.com:80/"), "http://example.com/")

    def test_preserves_non_default_port(self) -> None:
        self.assertEqual(_normalize_url("http://example.com:8080/"), "http://example.com:8080/")

    def test_adds_root_path_when_missing(self) -> None:
        self.assertEqual(_normalize_url("https://example.com"), "https://example.com/")

    def test_strips_query_and_fragment(self) -> None:
        self.assertEqual(
            _normalize_url("https://example.com/path?q=1#frag"),
            "https://example.com/path",
        )

    def test_strips_surrounding_whitespace(self) -> None:
        self.assertEqual(_normalize_url("  https://example.com/  "), "https://example.com/")

    def test_two_equivalent_urls_normalize_identically(self) -> None:
        a = _normalize_url("HTTP://Example.COM:80")
        b = _normalize_url("http://example.com/")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
