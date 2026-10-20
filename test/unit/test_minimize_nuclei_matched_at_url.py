import io
import runpy
import unittest
import urllib.parse
from typing import Callable

from artemis.reporting.modules.nuclei.poc_url_utils import (
    MAX_REFUZZ_CALLS_PER_FINDING,
    RefuzzError,
    minimize_nuclei_matched_at_url,
)


def _param_names(url: str) -> list[str]:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True).keys())


def _raw_query(url: str) -> str:
    return urllib.parse.urlparse(url).query


def _reproduces_when_present(*required: str) -> Callable[[str], bool]:
    """Fake reproduces_fn (a multiple-mode re-fuzz): the finding reproduces as
    long as all of ``required`` are still in the URL."""

    def reproduces(url: str) -> bool:
        return set(required) <= set(_param_names(url))

    return reproduces


def _large_dast_url(payloads: dict[str, str], total: int = 122) -> str:
    """A matched-at URL like the ones built from the DAST wordlists: ``total``
    parameters carrying a payload, with ``payloads`` placed among them."""
    filler = [f"p{i}=%27%22%3Etesting" for i in range(total - len(payloads))]
    raw_pairs = filler[: total // 3] + [f"{name}={value}" for name, value in payloads.items()] + filler[total // 3 :]
    return "http://example.com/list.php?" + "&".join(raw_pairs)


class _Counted:
    def __init__(self, fn: Callable[[str], bool]) -> None:
        self.fn = fn
        self.calls: list[str] = []

    def __call__(self, url: str) -> bool:
        self.calls.append(url)
        return self.fn(url)


class TestMinimizeNucleiMatchedAtUrl(unittest.TestCase):
    SORTBY_PAYLOAD = "1%27%29%20AND%20%28SELECT%201%29--%20-"

    def test_culprit_among_122_params(self) -> None:
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})
        reproduces = _Counted(_reproduces_when_present("sortby"))
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces)
        self.assertEqual(result, "http://example.com/list.php?sortby=" + self.SORTBY_PAYLOAD)
        self.assertLessEqual(len(reproduces.calls), MAX_REFUZZ_CALLS_PER_FINDING)

    def test_culprit_at_either_end(self) -> None:
        for position in (0, 121):
            raw_pairs = [f"p{i}=testing" for i in range(121)]
            raw_pairs.insert(position, "dest=%2F%2Fevil.example.com%2F")
            url = "http://example.com/?" + "&".join(raw_pairs)
            result = minimize_nuclei_matched_at_url(url, reproduces_fn=_reproduces_when_present("dest"))
            self.assertEqual(_raw_query(result), "dest=%2F%2Fevil.example.com%2F")

    def test_payload_preserved_byte_for_byte(self) -> None:
        url = "http://example.com/?url=%2F%2Fevil.example.com%2F&a=testing&b=testing"
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=_reproduces_when_present("url"))
        self.assertEqual(_raw_query(result), "url=%2F%2Fevil.example.com%2F")

    def test_equals_sign_in_value_preserved(self) -> None:
        url = "http://example.com/?redirect=http://evil/?a=b%26c=d&x=testing&y=testing&z=testing"
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=_reproduces_when_present("redirect"))
        self.assertEqual(_raw_query(result), "redirect=http://evil/?a=b%26c=d")

    def test_param_without_value_preserved(self) -> None:
        url = "http://example.com/?debug&next=PAYLOAD&a=testing&b=testing"
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=_reproduces_when_present("debug", "next"))
        self.assertEqual(_raw_query(result), "debug&next=PAYLOAD")

    def test_original_order_preserved(self) -> None:
        url = "http://example.com/?zzz=PAYLOAD&mmm=testing&aaa=PAYLOAD&nnn=testing"
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=_reproduces_when_present("aaa", "zzz"))
        self.assertEqual(_raw_query(result), "zzz=PAYLOAD&aaa=PAYLOAD")

    def test_urls_given_to_nuclei_carry_the_raw_segments(self) -> None:
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})
        reproduces = _Counted(_reproduces_when_present("sortby"))
        minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces)
        raw_segments = set(_raw_query(url).split("&"))
        for called_url in reproduces.calls:
            self.assertLessEqual(set(_raw_query(called_url).split("&")), raw_segments)

    def test_gated_finding_keeps_both_params(self) -> None:
        """`search` is only reflected while `login` is present, so both stay."""
        url = _large_dast_url({"login": "%27%22%3Etesting", "search": "%27%22%3E%3Cx%3E"})
        reproduces = _Counted(_reproduces_when_present("search", "login"))
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces)
        self.assertEqual(_raw_query(result), "login=%27%22%3Etesting&search=%27%22%3E%3Cx%3E")
        self.assertLessEqual(len(reproduces.calls), MAX_REFUZZ_CALLS_PER_FINDING)

    def test_gated_finding_with_params_far_apart_keeps_both_within_budget(self) -> None:
        raw_pairs = [f"p{i}=%27%22%3Etesting" for i in range(120)]
        raw_pairs.insert(10, "login=testing")
        raw_pairs.insert(90, "search=%27%22%3E%3Cx%3E")
        url = "http://example.com/?" + "&".join(raw_pairs)
        reproduces = _Counted(_reproduces_when_present("search", "login"))
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces)
        self.assertEqual(len(reproduces.calls), MAX_REFUZZ_CALLS_PER_FINDING)
        self.assertNotEqual(result, url)
        self.assertLessEqual({"login", "search"}, set(_param_names(result)))

    def test_budget_is_a_hard_limit(self) -> None:
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})
        for budget in (1, 2, 5, 10):
            reproduces = _Counted(_reproduces_when_present("sortby"))
            result = minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces, max_refuzz_calls=budget)
            self.assertLessEqual(len(reproduces.calls), budget)
            # Whatever is returned must still reproduce.
            self.assertTrue(_reproduces_when_present("sortby")(result))

    def test_original_order_preserved_when_the_budget_runs_out(self) -> None:
        """The partial result returned when the budget runs out keeps the
        original parameter order too - ddmin tests subsets as keep + candidates,
        so it must not return them in that order."""
        raw_pairs = [f"p{i}=testing" for i in range(120)]
        raw_pairs.insert(10, "login=testing")
        raw_pairs.insert(90, "search=%27%22%3E%3Cx%3E")
        url = "http://example.com/?" + "&".join(raw_pairs)
        shortened = 0
        for budget in range(3, MAX_REFUZZ_CALLS_PER_FINDING + 1):
            result = minimize_nuclei_matched_at_url(
                url, reproduces_fn=_reproduces_when_present("search", "login"), max_refuzz_calls=budget
            )
            kept = _raw_query(result).split("&")
            self.assertEqual(kept, [pair for pair in raw_pairs if pair in kept])
            self.assertLess(kept.index("login=testing"), kept.index("search=%27%22%3E%3Cx%3E"))
            shortened += result != url
        self.assertTrue(shortened)

    def test_result_rejected_by_the_final_check_falls_back_to_full(self) -> None:
        """A hit that does not repeat (e.g. a flaky target) must not shorten
        the PoC: the final re-fuzz of the shortened URL decides."""
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})
        seen: set[str] = set()

        def flaky(called_url: str) -> bool:
            if called_url in seen:
                return False
            seen.add(called_url)
            return "sortby" in _param_names(called_url)

        reproduces = _Counted(flaky)
        result = minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces)
        self.assertEqual(result, url)
        self.assertEqual(_param_names(reproduces.calls[-1]), ["sortby"])

    def test_not_reproducing_falls_back_to_full(self) -> None:
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})
        reproduces = _Counted(lambda _: False)
        self.assertEqual(minimize_nuclei_matched_at_url(url, reproduces_fn=reproduces), url)
        self.assertEqual(len(reproduces.calls), 1)

    def test_nuclei_error_falls_back_to_full(self) -> None:
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})

        def failing(called_url: str) -> bool:
            if len(_param_names(called_url)) < 50:
                raise RefuzzError("timeout")
            return "sortby" in _param_names(called_url)

        self.assertEqual(minimize_nuclei_matched_at_url(url, reproduces_fn=failing), url)

    def test_no_reproduces_fn_returns_full(self) -> None:
        url = _large_dast_url({"sortby": self.SORTBY_PAYLOAD})
        self.assertEqual(minimize_nuclei_matched_at_url(url, reproduces_fn=None), url)

    def test_few_params_not_minimized(self) -> None:
        short = "http://example.com/?a=1&b=2"
        reproduces = _Counted(_reproduces_when_present("a"))
        self.assertEqual(minimize_nuclei_matched_at_url(short, reproduces_fn=reproduces), short)
        self.assertEqual(reproduces.calls, [])

    def test_no_query_returned_unchanged(self) -> None:
        url = "http://example.com/path"
        self.assertEqual(minimize_nuclei_matched_at_url(url, reproduces_fn=_reproduces_when_present("a")), url)


class TestMinimizationSummaryLog(unittest.TestCase):
    URL = _large_dast_url({"sortby": "%27"})

    def _log_line(self, reproduces_fn: Callable[[str], bool]) -> str:
        with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
            minimize_nuclei_matched_at_url(self.URL, reproduces_fn=reproduces_fn, template_id="sqli-error-based")
        (line,) = logs.output
        # Never the URL, host or payload.
        self.assertNotIn("example.com", line)
        self.assertNotIn("%27", line)
        return line

    def test_shortened(self) -> None:
        self.assertRegex(
            self._log_line(_reproduces_when_present("sortby")),
            r"PoC minimization: template=sqli-error-based params=122->1 outcome=shortened ddmin_calls=\d+ "
            r"elapsed=\d+s$",
        )

    def test_fallback_no_reproduce(self) -> None:
        self.assertRegex(
            self._log_line(lambda _: False),
            r"params=122->122 outcome=fallback_no_reproduce ddmin_calls=1 elapsed=\d+s$",
        )

    def test_fallback_budget(self) -> None:
        with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
            minimize_nuclei_matched_at_url(
                self.URL, reproduces_fn=_reproduces_when_present("sortby"), template_id="x", max_refuzz_calls=2
            )
        self.assertRegex(logs.output[0], r"params=122->122 outcome=fallback_budget ddmin_calls=1 elapsed=\d+s$")

    def test_limit_below_minimum(self) -> None:
        """A limit below 2 cannot shorten anything; the line says so rather
        than looking like an ordinary exhausted budget."""
        for limit in (0, 1):
            reproduces = _Counted(_reproduces_when_present("sortby"))
            with self.assertLogs("artemis.poc_minimization", level="INFO") as logs:
                result = minimize_nuclei_matched_at_url(self.URL, reproduces_fn=reproduces, max_refuzz_calls=limit)
            self.assertEqual(result, self.URL)
            self.assertEqual(reproduces.calls, [])
            self.assertRegex(
                logs.output[0], r"outcome=fallback_budget ddmin_calls=0 elapsed=\d+s error=limit_below_minimum$"
            )

    def test_fallback_error(self) -> None:
        def failing(_: str) -> bool:
            raise RefuzzError("timeout")

        self.assertRegex(
            self._log_line(failing),
            r"params=122->122 outcome=fallback_error ddmin_calls=1 elapsed=\d+s error=timeout$",
        )

    def test_logger_does_not_depend_on_the_root_level(self) -> None:
        """Production runs with the root logger at WARNING; the summary line has
        its own handler and level, so it is still emitted."""
        import logging

        logger = logging.getLogger("artemis.poc_minimization")
        self.assertEqual(logger.level, logging.INFO)
        self.assertFalse(logger.propagate)

        # Through the real handler (not assertLogs, which swaps the handlers),
        # with the root logger at WARNING.
        (handler,) = logger.handlers
        assert isinstance(handler, logging.StreamHandler)
        stream = io.StringIO()
        previous_stream = handler.setStream(stream)
        root = logging.getLogger()
        previous_root_level = root.level
        root.setLevel(logging.WARNING)
        try:
            minimize_nuclei_matched_at_url(self.URL, reproduces_fn=lambda _: False, template_id="x")
        finally:
            root.setLevel(previous_root_level)
            handler.setStream(previous_stream)
        self.assertIn("PoC minimization: template=x params=122->122 outcome=fallback_no_reproduce", stream.getvalue())

    def test_reimport_does_not_add_handlers(self) -> None:
        """Every import of the module (reloads, test runners importing it in
        several ways) must keep exactly one handler - otherwise each line
        would be printed several times."""
        import logging

        from artemis.reporting.modules.nuclei import poc_url_utils

        # Run the module code again in a fresh namespace rather than reloading
        # it - a reload would replace RefuzzError under the other tests' feet.
        for _ in range(3):
            runpy.run_path(poc_url_utils.__file__)
        self.assertEqual(len(logging.getLogger("artemis.poc_minimization").handlers), 1)


if __name__ == "__main__":
    unittest.main()
