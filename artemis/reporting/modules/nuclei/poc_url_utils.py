"""Shorten Nuclei DAST PoC URLs, which stack 100+ wordlist parameters onto one
URL all carrying the payload.

ddmin (not Nuclei's reported ``fuzzing_parameter``, which is unreliable here)
finds a minimal subset of parameters that still reproduces the finding, within
a budget; the shortened URL is re-fuzzed and kept only if it still reproduces,
else the full URL is returned so the PoC always works.

When the URL Nuclei fuzzed is known (the finding's ``url``), the subsets are
re-fuzzed from it - with the original values, so Nuclei applies the payload
once, as it did in the scan - while the shortened PoC is cut out of matched-at.

Query parameters are split and preserved byte-for-byte - re-encoding via
parse_qs/urlencode would normalise payloads (``%2F%2F`` -> ``//``) and could
break them.
"""

import hashlib
import time
import urllib.parse
from typing import (
    Callable,
    Generic,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

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


def _group_value_segments(query: str) -> List[str]:
    """Split a raw query into parameters without a base URL to walk (see
    ``align_query_pairs``): Nuclei leaves ``&`` in a payload unencoded, and a
    segment without ``=`` cannot be a parameter of its own, so it stays with
    the one before it."""
    groups: List[List[str]] = []
    for segment in query.split("&"):
        if groups and "=" not in segment:
            groups[-1].append(segment)
        elif segment:
            groups.append([segment])
    return ["&".join(group) for group in groups]


def _with_the_payload(aligned: Optional[List[Tuple[str, str]]], kept: List[int]) -> List[int]:
    """The parameters a PoC shows: ``kept``, plus - if none of them carries
    the payload, as when ``align_query_pairs`` gave the text of a payload with
    "&name=" to the next parameter - the parameters that do."""
    if aligned is None:
        return kept
    changed = [i for i, (base, matched) in enumerate(aligned) if base != matched]
    if not changed or any(i in changed for i in kept):
        return kept
    return sorted(set(kept) | set(changed))


def _split_url(url: str) -> Tuple[str, str]:
    """Split a URL into the part before the query and the raw query.

    The query is everything after the first ``?``: Nuclei sends a ``#`` in a
    payload as it is (open-redirect-bypass, response-ssrf, time-based-sqli,
    blind-oast-polyglots have such payloads), so it does not start a fragment
    there - urlparse would cut the query short at it.
    """
    before, _, query = url.partition("?")
    return before, query


def _join_url(before: str, pairs: List[str]) -> str:
    return before + "?" + "&".join(pairs)


def count_query_params(url: str) -> int:
    return len(_split_query_pairs(_split_url(url)[1]))


def _url_sha(url: str) -> str:
    # Lets the logs show the same PoC minimized more than once without
    # carrying the URL.
    return hashlib.sha256(url.encode("utf-8", errors="surrogateescape")).hexdigest()[:12]


def log_not_minimized(url: str, template_id: str, outcome: str, error: str = "") -> None:
    """The summary line of a finding that is left unshortened without a re-fuzz."""
    params = count_query_params(url)
    summary_logger.info(
        "PoC minimization: template=%s params=%d->%d outcome=%s ddmin_calls=0 elapsed=0s url_sha=%s%s",
        template_id,
        params,
        params,
        outcome,
        _url_sha(url),
        f" error={error}" if error else "",
    )


def align_query_pairs(base_url: str, matched_url: str, strict: bool = True) -> Optional[List[Tuple[str, str]]]:
    """Pair every parameter of ``base_url`` - the URL Nuclei fuzzed - with its
    raw form in ``matched_url``, the matched-at URL of the finding.

    Nuclei leaves ``&`` in a payload unencoded, so one fuzzed value can span
    several ``&``-separated segments of matched-at; they are grouped back
    under their parameter by walking the base parameters in order. Returns
    None when the two URLs do not line up (another path, a parameter
    missing).

    ``strict=False`` skips the check that every fuzzed parameter got the same
    text, for the request of a canary: there every parameter carries an OAST
    URL of its own, and Nuclei moves the segments of a payload with ``&``
    that are the same in every parameter behind the first one.
    """
    base_before, base_query = _split_url(base_url)
    matched_before, matched_query = _split_url(matched_url)
    if base_before != matched_before:
        return None
    base_pairs = _split_query_pairs(base_query)
    if not base_pairs:
        return None

    groups: List[List[str]] = []
    for segment in matched_query.split("&"):
        name = urllib.parse.unquote_plus(segment.split("=", 1)[0])
        if segment and len(groups) < len(base_pairs) and name == base_pairs[len(groups)][0]:
            groups.append([segment])
        elif groups:
            groups[-1].append(segment)
        else:
            return None
    if len(groups) != len(base_pairs):
        return None
    aligned = [(raw_base, "&".join(group)) for (_, raw_base), group in zip(base_pairs, groups)]

    if strict and any(len(group) > 1 for group in groups):
        # Segments were glued to the parameter before them. That is right for
        # a payload with "&" - but so it would look if matched-at had a
        # parameter the base URL lacks. In multiple mode every fuzzed
        # parameter got the same payload, so a real split adds the same text
        # to all of them.
        def added(base: str, fuzzed: str) -> str:
            return fuzzed[len(base) :] if fuzzed.startswith(base) else fuzzed.split("=", 1)[-1]

        if len({added(base, fuzzed) for base, fuzzed in aligned if base != fuzzed}) != 1:
            return None
    return aligned


class _DdminResult(NamedTuple, Generic[T]):
    # The subset ddmin arrived at, in the original order; None if the full
    # set did not reproduce or could not be checked.
    result: Optional[List[T]]
    # The smallest subset a re-fuzz actually reported - ``result`` may be a
    # combination of two parts that was never re-fuzzed as a whole.
    confirmed: Optional[List[T]]
    # Why the search stopped early: None, "budget" or the RefuzzError message.
    stopped: Optional[str]


def _ddmin(items: Sequence[T], reproduces: Callable[[List[T]], bool], budget: int) -> _DdminResult[T]:
    """Delta debugging: find a small subset of ``items`` that still
    reproduces the finding, keeping the original order.

    Every subset kept along the way was confirmed by a re-fuzz, so when the
    search stops early (budget, timeout) the smallest one so far is the
    result.
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

    def subset(indices: List[int]) -> List[T]:
        return [items[i] for i in sorted(indices)]

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
            return _DdminResult(None, None, None)
    except _BudgetExhausted:
        return _DdminResult(None, None, "budget")
    except RefuzzError as e:
        return _DdminResult(None, None, str(e))

    try:
        result = reduce([], list(range(len(items))))
    except _BudgetExhausted:
        return _DdminResult(subset(best), subset(best), "budget")
    except RefuzzError as e:
        return _DdminResult(subset(best), subset(best), str(e))
    return _DdminResult(subset(result), subset(best), None)


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

    ``reproduces_fn`` gets the URL to re-fuzz: a subset of ``base_url`` - the
    URL Nuclei fuzzed - if it lines up with ``url``, else of ``url``.
    ``describe_fn`` adds fields to the summary line (e.g. how the re-fuzz was
    narrowed).
    """
    before, query = _split_url(url)
    if not query:
        return url

    aligned = align_query_pairs(base_url, url) if base_url else None
    if aligned is not None:
        base_before = _split_url(base_url or "")[0]
        refuzz_pairs = [base for base, _ in aligned]
        result_pairs = [matched for _, matched in aligned]
    else:
        base_before = before
        refuzz_pairs = result_pairs = _group_value_segments(query)

    # The payload went elsewhere than the query when the query came back
    # unchanged: into the path (reflected-xss also fuzzes it), a header or the
    # body (part: request). Then perhaps no parameter is needed at all, but
    # ddmin never tries an empty subset - it would keep an arbitrary one,
    # which the report would show as the vulnerable parameter.
    outside_query_from = _split_url(base_url)[0] if base_url and _split_url(base_url)[1] == query else None

    if len(result_pairs) <= params_threshold:
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

    def refuzz_url(indices: List[int]) -> str:
        return _join_url(base_before, [refuzz_pairs[i] for i in indices])

    def poc(indices: List[int]) -> Tuple[str, int]:
        shown = _with_the_payload(aligned, indices)
        return _join_url(before, [result_pairs[i] for i in shown]), len(shown)

    def finish(result: str, kept: int, outcome: str, error: str = "") -> str:
        details = describe_fn() if describe_fn else ""
        summary_logger.info(
            "PoC minimization: template=%s params=%d->%d outcome=%s ddmin_calls=%d elapsed=%ds base=%s url_sha=%s%s%s",
            template_id,
            len(result_pairs),
            kept,
            outcome,
            calls,
            round(time.monotonic() - started),
            "url" if aligned is not None else "matched_at",
            _url_sha(url),
            f" {details}" if details else "",
            f" error={error}" if error else "",
        )
        return result

    if max_refuzz_calls < 2:
        # ddmin needs at least one re-fuzz and the final check another, so a
        # lower limit (a misconfigured NUCLEI_REFUZZ_MAX_CALLS_PER_FINDING)
        # cannot shorten anything - say so instead of a plain fallback_budget,
        # which would read as "raise the limit a bit".
        return finish(url, len(result_pairs), "fallback_budget", error="limit_below_minimum")

    # One call is kept for the final check.
    search = _ddmin(
        list(range(len(result_pairs))),
        lambda subset: counted(refuzz_url(subset)),
        budget=max_refuzz_calls - 1,
    )
    kept, stopped = search.result, search.stopped

    if kept is None or len(kept) == len(result_pairs):
        # Nothing could be dropped - with 100+ parameters, only when the
        # search stopped before the first successful split.
        if stopped == "budget":
            return finish(url, len(result_pairs), "fallback_budget")
        if stopped:
            return finish(url, len(result_pairs), "fallback_error", error=stopped)
        return finish(url, len(result_pairs), "fallback_no_reproduce")

    if stopped and stopped != "budget":
        # Nuclei failed (typically a timeout) in the middle of the search.
        # Every subset ddmin kept was confirmed by a re-fuzz, so the smallest
        # so far is a working PoC - and one more re-fuzz of a target that
        # just timed out would most likely time out too.
        return finish(*poc(kept), "shortened_partial", error=stopped)

    # ddmin's result may be a combination it never tested as a whole, and
    # a flaky hit may have misled it - re-fuzz the shortened URL to make
    # sure it still reproduces before replacing the PoC.
    try:
        if not counted(refuzz_url(kept)):
            return finish(url, len(result_pairs), "fallback_no_reproduce")
    except RefuzzError as e:
        # The check could not be made: fall back to the smallest subset a
        # re-fuzz did report, if it is shorter than the full URL.
        confirmed = search.confirmed
        if confirmed is not None and len(confirmed) < len(result_pairs):
            return finish(*poc(confirmed), "shortened_partial", error=str(e))
        return finish(url, len(result_pairs), "fallback_error", error=str(e))

    if outside_query_from is not None:
        # Re-fuzzed from the original path, which Nuclei fuzzes again.
        try:
            if counted(outside_query_from):
                return finish(before, 0, "shortened")
        except RefuzzError:
            pass

    if stopped == "budget":
        return finish(*poc(kept), "shortened_partial", error="budget")
    return finish(*poc(kept), "shortened")


def minimize_oob_matched_at_url(
    url: str,
    attribute_fn: Callable[[], Set[int]],
    reproduces_fn: Callable[[str], bool],
    base_url: Optional[str],
    template_id: str = "unknown",
    params_threshold: int = 2,
    describe_fn: Optional[Callable[[], str]] = None,
) -> str:
    """Shorten the PoC URL of an out-of-band (interactsh) finding.

    ddmin does not work here: every check would wait for a callback. Instead
    ``attribute_fn`` re-fuzzes the URL Nuclei fuzzed (``base_url``) once, with
    an OAST URL of its own in every parameter, and returns the indices of the
    parameters whose URL called back; ``reproduces_fn`` then checks the URL
    cut down to them, waiting for one more callback - two waits per finding,
    whatever the number of parameters. If either gets no callback, the full
    URL is kept.
    """
    started = time.monotonic()
    aligned = align_query_pairs(base_url, url) if base_url else None
    total = len(aligned) if aligned is not None else count_query_params(url)

    def finish(result: str, kept: int, outcome: str, error: str = "") -> str:
        details = describe_fn() if describe_fn else ""
        summary_logger.info(
            "PoC minimization: template=%s params=%d->%d outcome=%s oob=1 elapsed=%ds url_sha=%s%s%s",
            template_id,
            total,
            kept,
            outcome,
            round(time.monotonic() - started),
            _url_sha(url),
            f" {details}" if details else "",
            f" error={error}" if error else "",
        )
        return result

    if total <= params_threshold:
        return url
    if aligned is None:
        # The parameters can only be given their own OAST URLs when re-fuzzed
        # from the URL Nuclei fuzzed.
        return finish(url, total, "fallback_error", error="url_not_aligned")

    try:
        attributed = sorted(attribute_fn())
    except RefuzzError as e:
        return finish(url, total, "fallback_error", error=str(e))
    if not attributed:
        # The target did not call back again.
        return finish(url, total, "fallback_no_reproduce")
    if len(attributed) == total:
        # Every parameter called back - the target fetches whatever URL it
        # gets, say. Any one of them will do; the check below confirms it.
        attributed = attributed[:1]

    try:
        shortened_reproduces = reproduces_fn(
            _join_url(_split_url(base_url or "")[0], [aligned[i][0] for i in attributed])
        )
    except RefuzzError as e:
        return finish(url, total, "fallback_error", error=str(e))
    if not shortened_reproduces:
        # E.g. the parameter only works together with another one.
        return finish(url, total, "fallback_no_reproduce", error="shortened_no_callback")
    shown = _with_the_payload(aligned, attributed)
    return finish(_join_url(_split_url(url)[0], [aligned[i][1] for i in shown]), len(shown), "shortened")
