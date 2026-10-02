"""Shorten Nuclei DAST PoC URLs, which stack 100+ wordlist parameters onto one
URL all carrying the payload.

ddmin (not Nuclei's reported ``fuzzing_parameter``, which is unreliable here)
finds a minimal subset of parameters that still reproduces the finding, within
a budget; the shortened URL is re-fuzzed and kept only if it still reproduces,
else the full URL is returned so the PoC always works.

Query parameters are split and preserved byte-for-byte - re-encoding via
parse_qs/urlencode would normalise payloads (``%2F%2F`` -> ``//``) and could
break them.
"""

import logging
import time
import urllib.parse
from typing import Callable, List, Optional, Sequence, Tuple, TypeVar

from artemis.config import Config
from artemis.log_context import RunContextFilter

# The default limit of Nuclei re-fuzzes for one finding, the final check
# included; nuclei.py passes NUCLEI_REFUZZ_MAX_CALLS_PER_FINDING instead.
MAX_REFUZZ_CALLS_PER_FINDING = 20

# One summary line per minimized finding, without the URL, host or payload, so
# that the outcome rate can be tracked. It gets its own handler: module loggers
# have none and inherit the root logger's default WARNING level, so these INFO
# lines would otherwise never reach the logs.
summary_logger = logging.getLogger("artemis.poc_minimization")
summary_logger.setLevel(logging.INFO)
summary_logger.propagate = False
if not summary_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(Config.Miscellaneous.LOGGING_FORMAT_STRING))
    # LOGGING_FORMAT_STRING references run_hash, which this filter sets.
    _handler.addFilter(RunContextFilter())
    summary_logger.addHandler(_handler)

T = TypeVar("T")


class RefuzzError(Exception):
    """Raised by a ``reproduces_fn`` that could not get an answer from Nuclei
    (timeout, crash, missing binary). Minimization is abandoned then."""


class _BudgetExhausted(Exception):
    pass


def _split_query_pairs(query: str) -> List[Tuple[str, str]]:
    """Split a raw query string into (decoded_name, raw_pair) tuples.

    ``raw_pair`` is the original ``name=value`` substring, preserved verbatim so
    the payload is never re-encoded.
    """
    pairs: List[Tuple[str, str]] = []
    for raw_pair in query.split("&"):
        if not raw_pair:
            continue
        raw_name = raw_pair.split("=", 1)[0]
        decoded_name = urllib.parse.unquote_plus(raw_name)
        pairs.append((decoded_name, raw_pair))
    return pairs


def _ddmin(items: Sequence[T], reproduces: Callable[[List[T]], bool], budget: int) -> Tuple[Optional[List[T]], bool]:
    """Delta debugging: return a small subset of ``items`` that still
    reproduces the finding, keeping the original order, and whether the budget
    ran out.
    """
    calls = 0
    best = list(range(len(items)))

    def test(indices: List[int]) -> bool:
        nonlocal calls, best
        if calls >= budget:
            raise _BudgetExhausted()
        calls += 1
        if reproduces([items[i] for i in sorted(indices)]):
            if len(indices) < len(best):
                best = sorted(indices)
            return True
        return False

    def reduce(keep: List[int], candidates: List[int]) -> List[int]:
        # Invariant: keep + candidates reproduces.
        if len(candidates) <= 1:
            return candidates
        first, second = candidates[: len(candidates) // 2], candidates[len(candidates) // 2 :]
        if test(keep + first):
            return reduce(keep, first)
        if test(keep + second):
            return reduce(keep, second)
        # Both halves are needed: minimize each while keeping the other.
        first = reduce(keep + second, first)
        return first + reduce(keep + first, second)

    try:
        if not test(best):
            return None, False
    except _BudgetExhausted:
        return None, True

    try:
        result = reduce([], list(range(len(items))))
    except _BudgetExhausted:
        return [items[i] for i in best], True
    return [items[i] for i in sorted(result)], False


def minimize_nuclei_matched_at_url(
    url: str,
    reproduces_fn: Optional[Callable[[str], bool]] = None,
    template_id: str = "unknown",
    params_threshold: int = 2,
    max_refuzz_calls: int = MAX_REFUZZ_CALLS_PER_FINDING,
) -> str:
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url

    pairs = _split_query_pairs(parsed.query)

    if len(pairs) <= params_threshold:
        # Don't minimize if there are not many parameters
        return url

    if reproduces_fn is None:
        return url

    started = time.monotonic()
    calls = 0

    def counted(candidate_url: str) -> bool:
        nonlocal calls
        calls += 1
        return reproduces_fn(candidate_url)

    def rebuild(raw_pairs: List[str]) -> str:
        return urllib.parse.urlunparse(parsed._replace(query="&".join(raw_pairs)))

    def finish(result: str, kept: int, outcome: str, error: str = "") -> str:
        summary_logger.info(
            "PoC minimization: template=%s params=%d->%d outcome=%s ddmin_calls=%d elapsed=%ds%s",
            template_id,
            len(pairs),
            kept,
            outcome,
            calls,
            round(time.monotonic() - started),
            f" error={error}" if error else "",
        )
        return result

    if max_refuzz_calls < 2:
        # ddmin needs at least one re-fuzz and the final check another, so a
        # lower limit (a misconfigured NUCLEI_REFUZZ_MAX_CALLS_PER_FINDING)
        # cannot shorten anything - say so instead of a plain fallback_budget,
        # which would read as "raise the limit a bit".
        return finish(url, len(pairs), "fallback_budget", error="limit_below_minimum")

    try:
        # One call is kept for the final check.
        kept_raw, budget_exhausted = _ddmin(
            [raw_pair for _, raw_pair in pairs],
            lambda subset: counted(rebuild(subset)),
            budget=max_refuzz_calls - 1,
        )

        if kept_raw is None:
            return finish(url, len(pairs), "fallback_budget" if budget_exhausted else "fallback_no_reproduce")

        if len(kept_raw) == len(pairs):
            # Nothing could be dropped - with 100+ parameters, only when the
            # budget ran out before the first successful split.
            return finish(url, len(pairs), "fallback_budget" if budget_exhausted else "fallback_no_reproduce")

        minimized = rebuild(kept_raw)

        # ddmin's result may be a combination it never tested as a whole, and
        # a flaky hit may have misled it - re-fuzz the shortened URL to make
        # sure it still reproduces before replacing the PoC.
        if not counted(minimized):
            return finish(url, len(pairs), "fallback_no_reproduce")
    except RefuzzError as e:
        return finish(url, len(pairs), "fallback_error", error=str(e))

    return finish(minimized, len(kept_raw), "shortened")
