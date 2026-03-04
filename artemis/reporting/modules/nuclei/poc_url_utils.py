"""Utilities for minimizing Nuclei DAST PoC URLs."""

import urllib.parse
from typing import Callable, Optional


def _build_single_param_url(parsed: urllib.parse.ParseResult, param_name: str, param_values: list[str]) -> str:
    useful_params = {param_name: param_values}
    new_query = urllib.parse.urlencode(
        useful_params,
        doseq=True,
        quote_via=urllib.parse.quote,
        safe="/:@!$&'()*+,;=",
    )
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def minimize_nuclei_matched_at_url(
    url: str,
    fuzzing_parameter: Optional[str] = None,
    verify_url_fn: Optional[Callable[[str], bool]] = None,
    params_threshold: int = 4,
) -> str:
    """Return a short, still-working PoC URL from a Nuclei matched-at URL.

    If fuzzing_parameter is provided, keeps only that parameter.
    If fuzzing_parameter is absent but verify_url_fn is provided, tries each
    query parameter individually to find which one triggers the vulnerability.
    Falls back to the original URL if verification fails or is unavailable.
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if len(params) <= params_threshold:
        # Don't minimize if there are not many parameters
        return url

    if fuzzing_parameter:
        if fuzzing_parameter not in params:
            return url
        minimized = _build_single_param_url(parsed, fuzzing_parameter, params[fuzzing_parameter])
        if verify_url_fn is not None and not verify_url_fn(minimized):
            return url
        return minimized

    if verify_url_fn is not None:
        for param_name, param_values in params.items():
            minimized = _build_single_param_url(parsed, param_name, param_values)
            if verify_url_fn(minimized):
                return minimized

    return url
