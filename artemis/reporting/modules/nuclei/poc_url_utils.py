"""Utilities for minimizing Nuclei DAST PoC URLs.

A DAST target built by Artemis carries *every* parameter from the DAST
wordlists (ssrf/redirect/lfi/cmdi/sqli/xss) stacked onto one URL - well over a
hundred parameters. Nuclei fuzzes them with ``-fuzzing-mode multiple``, so a
single hit's ``matched-at`` carries the payload in many parameters at once plus
all the unrelated scaffolding, which is why raw PoC URLs are thousands of
characters long. From a ``multiple`` hit we cannot tell which parameter is
actually vulnerable - the payload is in all of them.

To shorten the PoC we re-fuzz the finding in ``-fuzzing-mode single`` (one
parameter per request). That tells us exactly which parameters trigger the
vulnerability on their own; we keep those and drop the rest. If single-mode
confirms nothing (e.g. the vulnerability needs several parameters together,
which single-mode cannot reproduce), we fall back to the original URL so the
PoC still works.

Parameter values are preserved byte-for-byte from the raw query string: they
are attack payloads, and re-encoding them (e.g. decoding ``%2F%2F`` to ``//``)
could stop a payload from bypassing the very filter it was crafted to defeat.
We therefore split the query manually instead of going through parse_qs /
urlencode, which would normalise the encoding.
"""

import logging
import urllib.parse
from typing import Callable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


def _split_query_pairs(query: str) -> List[Tuple[str, str]]:
    """Split a raw query string into (decoded_name, raw_pair) tuples.

    ``raw_pair`` is the original ``name=value`` substring, preserved verbatim so
    the payload is never re-encoded. ``decoded_name`` is only used to match
    against confirmed parameter names.
    """
    pairs: List[Tuple[str, str]] = []
    for raw_pair in query.split("&"):
        if not raw_pair:
            continue
        raw_name = raw_pair.split("=", 1)[0]
        decoded_name = urllib.parse.unquote_plus(raw_name)
        pairs.append((decoded_name, raw_pair))
    return pairs


def minimize_nuclei_matched_at_url(
    url: str,
    refuzz_fn: Optional[Callable[[str], Set[str]]] = None,
    params_threshold: int = 2,
) -> str:
    """Return a short, still-working PoC URL from a Nuclei matched-at URL.

    ``refuzz_fn`` re-runs Nuclei in single fuzzing mode against ``url`` and
    returns the set of parameter names that trigger the finding on their own.
    We rebuild the URL keeping only those parameters, with their query segments
    preserved byte-for-byte. If ``refuzz_fn`` is absent, or confirms no
    parameter, the original URL is returned unchanged so the PoC still works.
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url

    pairs = _split_query_pairs(parsed.query)

    if len(pairs) <= params_threshold:
        # Don't minimize if there are not many parameters
        return url

    if refuzz_fn is None:
        return url

    confirmed = refuzz_fn(url)

    # Keep the raw query segments whose parameter name was confirmed, in their
    # original order and encoding.
    kept_raw = [raw_pair for decoded_name, raw_pair in pairs if decoded_name in confirmed]

    if not kept_raw:
        # Single-mode reproduced nothing (e.g. needs several params together) -
        # keep the full URL so the PoC still works. Logged (without the URL, to
        # avoid recording payloads/targets) so the fallback rate can be tracked.
        logger.info(
            "PoC minimization: single-mode confirmed no parameter, keeping full URL with %d params",
            len(pairs),
        )
        return url

    return urllib.parse.urlunparse(parsed._replace(query="&".join(kept_raw)))
