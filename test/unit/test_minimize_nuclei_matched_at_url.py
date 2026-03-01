import unittest
import urllib.parse

from artemis.reporting.modules.nuclei.poc_url_utils import minimize_nuclei_matched_at_url


def _params(url: str) -> dict[str, list[str]]:
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)


class TestMinimizeNucleiMatchedAtUrl(unittest.TestCase):
    """Tests for minimize_nuclei_matched_at_url.

    Strategy: if Nuclei's ``fuzzing_parameter`` is available, keep only that
    parameter in the URL.  Otherwise return the original URL unchanged so the
    recipient always has a working PoC.
    """

    def test_no_query_string_unchanged(self) -> None:
        url = "https://example.com/vuln.php"
        self.assertEqual(minimize_nuclei_matched_at_url(url, fuzzing_parameter="id"), url)

    def test_no_fuzzing_parameter_returns_full_url(self) -> None:
        """Without fuzzing_parameter the full URL is returned unchanged."""
        url = "http://example.com/?id=testing'&search=testing'&category=testing'"
        self.assertEqual(minimize_nuclei_matched_at_url(url), url)

    def test_fuzzing_parameter_keeps_only_named_param(self) -> None:
        """When fuzzing_parameter is given, keep only that one param."""
        url = "http://example.com/?filename=../../etc/passwd&file=abc.html&path=abc.html"
        result = minimize_nuclei_matched_at_url(url, fuzzing_parameter="filename")
        p = _params(result)
        self.assertEqual(list(p.keys()), ["filename"])
        self.assertEqual(p["filename"], ["../../etc/passwd"])

    def test_fuzzing_parameter_not_in_url_returns_full_url(self) -> None:
        """If the named param isn't in the URL, return it unchanged."""
        url = "http://example.com/?id=testing'&search=testing'"
        self.assertEqual(
            minimize_nuclei_matched_at_url(url, fuzzing_parameter="nonexistent"),
            url,
        )

    def test_real_lfi_url(self) -> None:
        """Matches the real Nuclei v3.7.0 output from test-dast-vuln-app."""
        url = "http://172.17.0.2:5000/?filename=../../../../../../../../../../../../../../../etc/passwd"
        result = minimize_nuclei_matched_at_url(url, fuzzing_parameter="filename")
        # Single param URL stays the same (just the one param)
        self.assertIn("filename=", result)
        self.assertIn("/etc/passwd", result)
        self.assertNotIn("&", result)

    def test_big_sqli_url_minimized(self) -> None:
        """The exact long URL from issue #1977 gets minimized to one param."""
        url = (
            "http://example.com/vulnerabilities/sqli.php"
            "?dest=http%3A%2F%2F127.0.0.1%2Fabc.html'"
            "&redirect=http%3A%2F%2F127.0.0.1%2Fabc.html'"
            "&id=testing'&search=testing'&category=testing'"
        )
        result = minimize_nuclei_matched_at_url(url, fuzzing_parameter="id")
        p = _params(result)
        self.assertEqual(list(p.keys()), ["id"])
        self.assertEqual(p["id"], ["testing'"])

    def test_slashes_not_encoded(self) -> None:
        """Path traversal slashes must stay readable, not become %2F."""
        url = "http://example.com/?file=../../etc/passwd&other=abc"
        result = minimize_nuclei_matched_at_url(url, fuzzing_parameter="file")
        self.assertIn("../../etc/passwd", result)
        self.assertNotIn("%2F", result)

    def test_path_host_scheme_preserved(self) -> None:
        url = "https://example.com:8443/api/v1/?file=../../etc/passwd&path=abc.html"
        result = minimize_nuclei_matched_at_url(url, fuzzing_parameter="file")
        parsed = urllib.parse.urlparse(result)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "example.com")
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(parsed.path, "/api/v1/")

    def test_verify_fn_passes_uses_minimized_url(self) -> None:
        """If verify_url_fn returns True, the minimized URL is used."""
        url = "http://example.com/?id=testing'&search=testing'&category=testing'"
        result = minimize_nuclei_matched_at_url(
            url,
            fuzzing_parameter="id",
            verify_url_fn=lambda _: True,
        )
        p = _params(result)
        self.assertEqual(list(p.keys()), ["id"])

    def test_verify_fn_fails_falls_back_to_original(self) -> None:
        """If verify_url_fn returns False (e.g. Nuclei doesn't find the vuln),
        the original URL is returned so the PoC stays valid."""
        url = "http://example.com/?id=testing'&required_param=abc"
        result = minimize_nuclei_matched_at_url(
            url,
            fuzzing_parameter="id",
            verify_url_fn=lambda _: False,  # simulates a broken minimized URL
        )
        self.assertEqual(result, url)


if __name__ == "__main__":
    unittest.main()
