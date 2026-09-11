import unittest
from typing import Any

from artemis.http_requests import HTTPResponse
from artemis.injection_helpers import (
    build_result_data,
    create_status_reason,
    deduplicate_findings,
    responses_differ,
)


def make_response(content: str, status_code: int = 200) -> HTTPResponse:
    return HTTPResponse(
        status_code=status_code,
        content_bytes=content.encode("utf-8"),
        encoding="utf-8",
        is_redirect=False,
        url="http://example.com/",
        headers={},
    )


class TestResponsesDiffer(unittest.TestCase):
    """responses_differ backs the blind/differential probes in the injection detectors: a
    difference between two responses is what proves a payload reached the query. Anything that
    isn't usable evidence must read as "not different" so that it cannot become a finding."""

    def test_identical_content_does_not_differ(self) -> None:
        self.assertFalse(responses_differ(make_response("hello world"), make_response("hello world")))

    def test_clearly_different_content_differs(self) -> None:
        self.assertTrue(responses_differ(make_response("a" * 100), make_response("b" * 100)))

    def test_missing_response_does_not_differ(self) -> None:
        # forgiving_http_get returns None when a request could not be completed - a failed
        # request is not evidence of anything.
        self.assertFalse(responses_differ(None, make_response("hello")))
        self.assertFalse(responses_differ(make_response("hello"), None))
        self.assertFalse(responses_differ(None, None))

    def test_server_error_does_not_differ(self) -> None:
        # A 5xx is noise (e.g. the server crashing on an unexpected parameter), not evidence,
        # even when the two bodies are completely different.
        self.assertFalse(responses_differ(make_response("a" * 100, status_code=500), make_response("b" * 100)))
        self.assertFalse(responses_differ(make_response("a" * 100), make_response("b" * 100, status_code=503)))

    def test_client_error_is_still_compared(self) -> None:
        # Only 5xx is excluded - a 404 vs 200 difference is a legitimate signal.
        self.assertTrue(responses_differ(make_response("a" * 100, status_code=404), make_response("b" * 100)))

    def test_threshold_is_respected(self) -> None:
        similar_a = make_response("the quick brown fox jumps over the lazy dog")
        similar_b = make_response("the quick brown fox jumps over the lazy cat")
        self.assertFalse(responses_differ(similar_a, similar_b))
        # The same pair counts as different once almost-perfect similarity is demanded.
        self.assertTrue(responses_differ(similar_a, similar_b, threshold=1.0))


class TestCreateStatusReason(unittest.TestCase):
    """create_status_reason builds the human-readable status_reason stored per task result."""

    def test_formats_url_and_statement(self) -> None:
        self.assertEqual(
            create_status_reason([{"url": "http://example.com/?a=1", "statement": "nosql_injection"}]),
            "http://example.com/?a=1: nosql_injection",
        )

    def test_deduplicates_repeated_findings(self) -> None:
        item = {"url": "http://example.com/", "statement": "nosql_injection"}
        self.assertEqual(create_status_reason([item, dict(item)]), "http://example.com/: nosql_injection")

    def test_output_is_sorted_and_therefore_stable(self) -> None:
        # The ordering must not depend on input order or on set iteration order, so that the same
        # findings always produce the same string across runs.
        findings: list[dict[str, Any]] = [
            {"url": f"http://{host}.example.com/", "statement": "nosql_injection"} for host in "ebadc"
        ]
        expected = ", ".join(f"http://{host}.example.com/: nosql_injection" for host in "abcde")
        self.assertEqual(create_status_reason(findings), expected)
        self.assertEqual(create_status_reason(list(reversed(findings))), expected)

    def test_empty_message_yields_empty_string(self) -> None:
        self.assertEqual(create_status_reason([]), "")

    def test_missing_keys_do_not_raise(self) -> None:
        self.assertEqual(create_status_reason([{}]), "None: None")


class TestDeduplicateFindings(unittest.TestCase):
    """deduplicate_findings drops repeated findings before they are saved as a task result."""

    def test_removes_exact_duplicates_keeping_first_seen_order(self) -> None:
        findings: list[dict[str, Any]] = [{"url": "b"}, {"url": "a"}, {"url": "b"}]
        self.assertEqual(deduplicate_findings(findings), [{"url": "b"}, {"url": "a"}])

    def test_key_order_does_not_affect_identity(self) -> None:
        # Findings are built by different code paths, so the same finding can arrive with its
        # keys in a different order - it is still a duplicate.
        findings: list[dict[str, Any]] = [{"url": "a", "code": "x"}, {"code": "x", "url": "a"}]
        self.assertEqual(deduplicate_findings(findings), [{"url": "a", "code": "x"}])

    def test_distinct_findings_are_kept(self) -> None:
        findings: list[dict[str, Any]] = [{"url": "a"}, {"url": "b"}]
        self.assertEqual(deduplicate_findings(findings), findings)

    def test_nested_values_are_compared_by_value(self) -> None:
        findings: list[dict[str, Any]] = [
            {"url": "a", "parameters": ["p", "q"]},
            {"url": "a", "parameters": ["p", "q"]},
            {"url": "a", "parameters": ["q", "p"]},
        ]
        self.assertEqual(len(deduplicate_findings(findings)), 2)

    def test_empty_input(self) -> None:
        self.assertEqual(deduplicate_findings([]), [])


class TestBuildResultData(unittest.TestCase):
    """build_result_data is the result envelope every injection detector saves."""

    def test_deduplicates_and_attaches_statements(self) -> None:
        statements = {"nosql_injection": "nosql_injection"}
        result = build_result_data([{"url": "a"}, {"url": "a"}], statements)
        self.assertEqual(result, {"result": [{"url": "a"}], "statements": statements})

    def test_extra_keys_are_merged(self) -> None:
        result = build_result_data([], {"s": "s"}, untestable_urls=["http://example.com/"])
        self.assertEqual(result["untestable_urls"], ["http://example.com/"])
        self.assertEqual(result["result"], [])

    def test_envelope_contains_result_extras_and_statements(self) -> None:
        # The full contract in one assertion: findings are deduplicated, detector-specific extras
        # are merged in alongside, and the statement map the reporter reads is preserved.
        statements = {"nosql_injection": "nosql_injection"}
        result = build_result_data(
            [{"url": "a"}, {"url": "a"}],
            statements,
            untestable_urls=["http://example.com/"],
            scanned_parameters=["q"],
        )
        self.assertEqual(
            result,
            {
                "result": [{"url": "a"}],
                "untestable_urls": ["http://example.com/"],
                "scanned_parameters": ["q"],
                "statements": statements,
            },
        )


if __name__ == "__main__":
    unittest.main()
