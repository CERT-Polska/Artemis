import unittest
from unittest.mock import MagicMock, patch

import requests

from artemis.crawling import _fetch_injectable_parameters, get_injectable_parameters


def _make_response(html: str) -> MagicMock:
    response = MagicMock()
    response.text = html
    response.__bool__ = lambda self: True
    return response


class TestGetInjectableParametersCache(unittest.TestCase):
    """Regression tests for the bug where lru_cache was caching empty lists
    produced by transient network failures, permanently masking injectable
    parameters for the affected URL."""

    def setUp(self) -> None:
        _fetch_injectable_parameters.cache_clear()

    def tearDown(self) -> None:
        _fetch_injectable_parameters.cache_clear()

    @patch("artemis.crawling.http_requests.get")
    def test_transient_failure_is_not_cached(self, mock_get: MagicMock) -> None:
        """A RequestException must bubble out of the cached helper so the
        empty result is NOT memoized."""
        mock_get.side_effect = requests.exceptions.ConnectionError("boom")

        url = "http://example.com/form"

        self.assertEqual(get_injectable_parameters(url), [])
        self.assertEqual(get_injectable_parameters(url), [])

        self.assertEqual(mock_get.call_count, 2)

    @patch("artemis.crawling.http_requests.get")
    def test_successful_response_is_cached(self, mock_get: MagicMock) -> None:
        """Successful parses must be cached — repeated lookups must not
        re-hit the network."""
        mock_get.return_value = _make_response(
            '<html><body><form><input name="username"><input name="password"></form></body></html>'
        )

        url = "http://example.com/login"

        first = get_injectable_parameters(url)
        second = get_injectable_parameters(url)

        self.assertEqual(sorted(first), ["password", "username"])
        self.assertEqual(sorted(second), ["password", "username"])
        self.assertEqual(mock_get.call_count, 1)

    @patch("artemis.crawling.http_requests.get")
    def test_failure_then_success_returns_fresh_result(self, mock_get: MagicMock) -> None:
        """This is the original bug: a transient failure followed by a
        successful request for the same URL must return the real params,
        not a stale empty list from the cache."""
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("transient"),
            _make_response('<html><input name="q"></html>'),
        ]

        url = "http://example.com/search"

        self.assertEqual(get_injectable_parameters(url), [])
        self.assertEqual(get_injectable_parameters(url), ["q"])

        self.assertEqual(mock_get.call_count, 2)

    @patch("artemis.crawling.http_requests.get")
    def test_different_urls_are_cached_independently_success_and_failure(self, mock_get: MagicMock) -> None:
        """Sanity check that the cache is keyed on the URL — a failure for
        one URL must not shadow a successful response for a different one."""
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("transient"),
            _make_response('<html><input name="email"></html>'),
        ]

        self.assertEqual(get_injectable_parameters("http://a.example/x"), [])
        self.assertEqual(get_injectable_parameters("http://b.example/y"), ["email"])

        self.assertEqual(mock_get.call_count, 2)

    @patch("artemis.crawling.http_requests.get")
    def test_different_urls_are_cached_independently_two_successes(self, mock_get: MagicMock) -> None:
        """Sanity check that the cache is keyed on the URL — data for
        one URL must not shadow a response for a different one."""
        mock_get.side_effect = [
            _make_response('<html><input name="name"></html>'),
            _make_response('<html><input name="email"></html>'),
        ]

        self.assertEqual(get_injectable_parameters("http://a.example/x"), ["name"])
        self.assertEqual(get_injectable_parameters("http://b.example/y"), ["email"])

        self.assertEqual(mock_get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
