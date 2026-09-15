import datetime
from timeit import default_timer as timer
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import requests


def has_query_parameters(url: str) -> bool:
    """Check whether a URL has query parameters."""
    return "?" in url or bool(urlparse(url).query)


def create_url_with_batch_payload(url: str, param_batch: Sequence[str], payload: str) -> str:
    """Append a batch of query parameters all assigned to the same payload to a URL."""
    assignments = {key: payload for key in param_batch}
    concatenation = "&" if has_query_parameters(url) else "?"
    return f"{url}{concatenation}" + "&".join([f"{key}={value}" for key, value in assignments.items()])


def change_url_params(url: str, payload: str, param_batch: Sequence[str]) -> str:
    """
    Replace existing query parameters in the URL with payload,
    and append any additional parameters in param_batch with the payload.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    params = list(query_params.keys())
    new_query_params = {}
    assignments = {key: payload for key in param_batch}

    for param in params:
        new_query_params[param] = [payload]

    new_query_string = urlencode(new_query_params, doseq=True)
    new_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query_string,
            parsed_url.fragment,
        )
    )
    concatenation = "&" if has_query_parameters(new_url) else "?"
    new_url = f"{new_url}" + concatenation + "&".join([f"{key}={value}" for key, value in assignments.items()])
    return unquote(new_url)


def measure_request_time(
    http_get_func: Callable[..., Any],
    url: str,
    timeout_threshold: float,
    headers: Optional[Dict[str, str]] = None,
) -> float:
    """Measure the time in seconds taken to perform a GET request."""
    start = timer()
    try:
        if headers is not None:
            http_get_func(url, headers=headers)
        else:
            http_get_func(url)
    except requests.exceptions.Timeout:
        return timeout_threshold
    return datetime.timedelta(seconds=timer() - start).seconds


def minimize_parameters(
    params: Sequence[str],
    test_func: Callable[[str], bool],
    max_len: Optional[int] = None,
) -> List[str]:
    """
    Try to find a minimal subset of parameters that satisfy test_func (which checks if param triggers the finding).
    If any individual parameter triggers the test, returns the list of matching parameters (up to max_len).
    Otherwise, returns the original params list.
    """
    minimal_params: List[str] = []
    for param in params:
        if test_func(param):
            minimal_params.append(param)
        if max_len is not None and len(minimal_params) >= max_len:
            break

    if minimal_params:
        return minimal_params
    return list(params)
