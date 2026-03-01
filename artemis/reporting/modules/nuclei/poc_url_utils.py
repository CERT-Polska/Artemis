"""Utilities for minimizing Nuclei DAST PoC URLs."""

import urllib.parse
from typing import Callable, Optional


def minimize_nuclei_matched_at_url(
    url: str,
    fuzzing_parameter: Optional[str] = None,
    verify_url_fn: Optional[Callable[[str], bool]] = None,
) -> str:
    """Return a short, still-working PoC URL from a Nuclei matched-at URL.

    Keeps only the fuzzing_parameter if provided, otherwise returns the
    original URL unchanged.

    If verify_url_fn is provided, it is called with the minimized URL.
    If it returns False (e.g. the app requires multiple parameters via isset()),
    the original URL is returned as a fallback so the PoC stays valid.
    """
    if not fuzzing_parameter:
        return url

    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if fuzzing_parameter not in params:
        return url

    useful_params = {fuzzing_parameter: params[fuzzing_parameter]}
    new_query = urllib.parse.urlencode(
        useful_params,
        doseq=True,
        quote_via=urllib.parse.quote,
        safe="/:@!$&'()*+,;=",
    )
    minimized = urllib.parse.urlunparse(parsed._replace(query=new_query))

    if verify_url_fn is not None and not verify_url_fn(minimized):
        return url

    return minimized
