import time
import unittest
from unittest.mock import MagicMock

import requests

from artemis.injection_utils import (
    change_url_params,
    create_url_with_batch_payload,
    has_query_parameters,
    measure_request_time,
    minimize_parameters,
)


class TestInjectionUtils(unittest.TestCase):
    def test_has_query_parameters(self) -> None:
        self.assertTrue(has_query_parameters("http://example.com/?id=1"))
        self.assertTrue(has_query_parameters("http://example.com/test?param=val"))
        self.assertTrue(has_query_parameters("http://example.com/?"))
        self.assertFalse(has_query_parameters("http://example.com"))
        self.assertFalse(has_query_parameters("http://example.com/path/to/page"))

    def test_create_url_with_batch_payload(self) -> None:
        url = "http://example.com/page"
        result = create_url_with_batch_payload(url, ["param1", "param2"], "test_payload")
        self.assertEqual(result, "http://example.com/page?param1=test_payload&param2=test_payload")

        url_with_params = "http://example.com/page?existing=1"
        result_with_params = create_url_with_batch_payload(url_with_params, ["param1"], "test_payload")
        self.assertEqual(result_with_params, "http://example.com/page?existing=1&param1=test_payload")

    def test_change_url_params(self) -> None:
        url = "http://example.com/page?id=old&other=value"
        result = change_url_params(url, "injected", ["extra"])
        self.assertIn("id=injected", result)
        self.assertIn("other=injected", result)
        self.assertIn("extra=injected", result)

    def test_measure_request_time(self) -> None:
        def fake_fast_get(url: str, **kwargs: object) -> None:
            pass

        def fake_slow_get(url: str, **kwargs: object) -> None:
            time.sleep(0.1)

        def fake_timeout_get(url: str, **kwargs: object) -> None:
            raise requests.exceptions.Timeout("Timed out")

        self.assertLess(measure_request_time(fake_fast_get, "http://example.com", 5.0), 1.0)
        self.assertGreaterEqual(measure_request_time(fake_slow_get, "http://example.com", 5.0), 0.0)
        self.assertEqual(measure_request_time(fake_timeout_get, "http://example.com", 5.0), 5.0)

    def test_minimize_parameters(self) -> None:
        params = ["a", "b", "c", "d", "e", "f"]

        # Only 'b' and 'd' trigger the condition
        minimal = minimize_parameters(params, test_func=lambda p: p in {"b", "d"}, max_len=5)
        self.assertEqual(minimal, ["b", "d"])

        # With capping
        minimal_capped = minimize_parameters(params, test_func=lambda p: p in {"a", "b", "c", "d"}, max_len=2)
        self.assertEqual(minimal_capped, ["a", "b"])

        # Fallback when none trigger
        minimal_fallback = minimize_parameters(params, test_func=lambda p: False, max_len=5)
        self.assertEqual(minimal_fallback, params)
