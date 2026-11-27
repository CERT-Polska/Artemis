"""Shorten Nuclei DAST PoC URLs, which stack 100+ wordlist parameters onto one
URL all carrying the payload.

ddmin (not Nuclei's reported ``fuzzing_parameter``, which is unreliable here)
finds a minimal subset of parameters that still reproduces the finding, within
a budget; the shortened URL is re-fuzzed and kept only if it still reproduces,
else the full URL is returned so the PoC always works. When Nuclei fails
half-way (typically a timeout), the smallest subset a re-fuzz confirmed is
used.

The subsets are re-fuzzed from the URL Nuclei fuzzed (the finding's ``url``),
with the original values, so Nuclei inserts the payload once, as in the scan;
the PoC is cut out of matched-at. Parameters are split and preserved
byte-for-byte - re-encoding via parse_qs/urlencode would normalise payloads
(``%2F%2F`` -> ``//``) and could break them.
"""

import time
import urllib.parse
from typing import Callable, List, Optional, Sequence, Tuple, TypeVar

from artemis.utils import build_logger

# The default limit of Nuclei re-fuzzes for one finding, the final check
# included; nuclei.py passes NUCLEI_REFUZZ_MAX_CALLS_PER_FINDING instead.
MAX_REFUZZ_CALLS_PER_FINDING = 20

summary_logger = build_logger("artemis.poc_minimization")

T = TypeVar("T")


class RefuzzError(Exception):
    """Raised by a ``reproduces_fn`` that could not get an answer from Nuclei
    (timeout, crash, missing binary). Minimization stops then."""


class _BudgetExhausted(Exception):
    pass


def _split_url(url: str) -> Tuple[str, str]:
    before, _, query = url.partition("?")
    return before, query


def _join_url(before: str, parameters: List[str]) -> str:
    return before + "?" + "&".join(parameters) if parameters else before


def _query_parameters(query: str) -> List[str]:
    """Split a raw query into its ``name=value`` parameters, byte-for-byte.

    Nuclei leaves ``&`` in a payload unencoded, and a segment without ``=``
    cannot be a parameter of its own, so it stays with the one before it.
    """
    parameters: List[str] = []
    for segment in query.split("&"):
        if parameters and "=" not in segment:
            parameters[-1] += "&" + segment
        elif segment:
            parameters.append(segment)
    return parameters


def _name(parameter: str) -> str:
    return urllib.parse.unquote_plus(parameter.split("=", 1)[0])


def _ddmin(
    items: Sequence[T], reproduces: Callable[[List[T]], bool], budget: int
) -> Tuple[Optional[List[T]], Optional[str]]:
    """Delta debugging: return a small subset of ``items`` that still
    reproduces the finding, keeping the original order, and why the search
    stopped early - None, "budget" or the RefuzzError message.

    Every subset kept along the way was confirmed by a re-fuzz, so when the
    search stops early the smallest one so far is returned (None if not even
    the full set was).
    """
    calls = 0
    best: Optional[List[int]] = None

    def subset(indices: List[int]) -> List[T]:
        return [items[i] for i in sorted(indices)]

    def test(indices: List[int]) -> bool:
        nonlocal calls, best
        if calls >= budget:
            raise _BudgetExhausted()
        calls += 1
        if reproduces(subset(indices)):
            if best is None or len(indices) < len(best):
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
        if not test(list(range(len(items)))):
            return None, None
        result = reduce([], list(range(len(items))))
    except _BudgetExhausted:
        stopped = "budget"
    except RefuzzError as e:
        stopped = str(e)
    else:
        return subset(result), None
    return (subset(best) if best is not None else None), stopped


def minimize_nuclei_matched_at_url(
    url: str,
    reproduces_fn: Optional[Callable[[str], bool]] = None,
    template_id: str = "unknown",
    params_threshold: int = 2,
    max_refuzz_calls: int = MAX_REFUZZ_CALLS_PER_FINDING,
    base_url: Optional[str] = None,
    describe_fn: Optional[Callable[[], str]] = None,
) -> str:
    """Return the shortest PoC URL (a part of ``url``, the matched-at URL)
    that ``reproduces_fn`` still reports, or ``url`` itself.

    ``reproduces_fn`` gets subsets of ``base_url`` - the URL Nuclei fuzzed -
    if its parameters line up with ``url``'s, else of ``url``.
    ``describe_fn`` adds fields to the summary line.
    """
    before, query = _split_url(url)
    matched = _query_parameters(query)

    if len(matched) <= params_threshold:
        # Don't minimize if there are not many parameters
        return url

    if reproduces_fn is None:
        return url

    refuzz_before, refuzz = before, matched
    if base_url:
        base_before, base_query = _split_url(base_url)
        base = _query_parameters(base_query)
        if [_name(parameter) for parameter in base] == [_name(parameter) for parameter in matched]:
            refuzz_before, refuzz = base_before, base
    from_url = refuzz is not matched

    started = time.monotonic()
    calls = 0

    def counted(candidate_url: str) -> bool:
        nonlocal calls
        calls += 1
        return reproduces_fn(candidate_url)

    def refuzz_url(indices: List[int]) -> str:
        return _join_url(refuzz_before, [refuzz[i] for i in indices])

    def poc(indices: List[int]) -> str:
        return _join_url(before, [matched[i] for i in indices])

    def finish(result: str, kept: int, outcome: str, error: str = "") -> str:
        details = describe_fn() if describe_fn else ""
        summary_logger.info(
            "PoC minimization: template=%s params=%d->%d outcome=%s ddmin_calls=%d elapsed=%ds%s%s%s",
            template_id,
            len(matched),
            kept,
            outcome,
            calls,
            round(time.monotonic() - started),
            " base=url" if from_url else "",
            f" {details}" if details else "",
            f" error={error}" if error else "",
        )
        return result

    if max_refuzz_calls < 2:
        # ddmin needs at least one re-fuzz and the final check another, so a
        # lower limit (a misconfigured NUCLEI_REFUZZ_MAX_CALLS_PER_FINDING)
        # cannot shorten anything - say so instead of a plain fallback_budget,
        # which would read as "raise the limit a bit".
        return finish(url, len(matched), "fallback_budget", error="limit_below_minimum")

    query_changed = refuzz != matched
    if from_url and not query_changed:
        # The query came back unchanged, so the payload went elsewhere: into
        # the path (reflected-xss fuzzes it too), a header or the body. Perhaps
        # no parameter is needed - ddmin never tries an empty subset, it would
        # keep an arbitrary one, which the PoC would show as the vulnerable one.
        try:
            if counted(refuzz_before):
                return finish(before, 0, "shortened")
        except RefuzzError:
            pass

    # One call is kept for the final check.
    kept, stopped = _ddmin(
        list(range(len(matched))),
        lambda indices: counted(refuzz_url(indices)),
        budget=max_refuzz_calls - 1 - calls,
    )

    if kept is None or len(kept) == len(matched):
        # Nothing could be dropped - with 100+ parameters, only when the
        # search stopped before the first successful split.
        if stopped == "budget":
            return finish(url, len(matched), "fallback_budget")
        if stopped:
            return finish(url, len(matched), "fallback_error", error=stopped)
        return finish(url, len(matched), "fallback_no_reproduce")

    if query_changed and all(refuzz[i] == matched[i] for i in kept):
        # None of the kept parameters carries the payload in matched-at - Nuclei
        # moves the parts of a payload with "&" that are the same in every
        # parameter behind the first one. Such a PoC would not show it.
        return finish(url, len(matched), "fallback_payload_missing")

    if stopped and stopped != "budget":
        # Nuclei failed (typically a timeout) in the middle of the search.
        # Every subset ddmin kept was confirmed by a re-fuzz, so the smallest
        # one is a working PoC - and one more re-fuzz of a target that has just
        # timed out would most likely time out too.
        return finish(poc(kept), len(kept), "shortened_partial", error=stopped)

    # ddmin's result may be a combination it never tested as a whole, and
    # a flaky hit may have misled it - re-fuzz the shortened URL to make
    # sure it still reproduces before replacing the PoC.
    try:
        if not counted(refuzz_url(kept)):
            return finish(url, len(matched), "fallback_no_reproduce")
    except RefuzzError as e:
        return finish(url, len(matched), "fallback_error", error=str(e))

    if stopped == "budget":
        return finish(poc(kept), len(kept), "shortened_partial", error="budget")
    return finish(poc(kept), len(kept), "shortened")
