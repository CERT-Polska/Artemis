import functools
import urllib
from typing import List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from bs4.exceptions import ParserRejectedMarkup  # type: ignore

from artemis import http_requests


def get_links_and_resources_on_same_domain(url: str) -> List[str]:
    url_parsed = urllib.parse.urlparse(url)
    try:
        response = http_requests.get(url)
    except requests.exceptions.RequestException:
        return []

    soup = BeautifulSoup(response.text)
    links = []
    for tag in soup.find_all():
        new_url = None
        for attribute in ["src", "href"]:
            if attribute not in tag.attrs:
                continue

            new_url = urllib.parse.urljoin(url, tag[attribute])
            new_url_parsed = urllib.parse.urlparse(new_url)

            # Let's be lax and allow resources from different ports (or e.g. http vs https)
            if url_parsed.hostname == new_url_parsed.hostname:
                links.append(new_url.split("#")[0])
    return list(set(links))


@functools.lru_cache(maxsize=8192)
def _fetch_injectable_parameters(url: str) -> Tuple[str, ...]:
    response = http_requests.get(url)
    if not response:
        return ()

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except ParserRejectedMarkup:
        return ()

    result = set()
    for input_tag in soup.find_all("input"):
        if input_tag.get("name"):
            result.add(input_tag.get("name"))
    return tuple(result)


def get_injectable_parameters(url: str) -> List[str]:
    try:
        return list(_fetch_injectable_parameters(url))
    except Exception:
        return []


def add_injectable_params_and_common_params_from_wordlist(
    url: str, params_wordlist: str, default_param_value: str = ""
) -> str:
    with open(params_wordlist, "r") as file:
        params = file.read().splitlines()
        params = [
            param.strip() for param in params if param.strip() and not param.startswith("#")
        ] + get_injectable_parameters(url)

    parsed_url = urlparse(url)

    query_params = parse_qs(parsed_url.query)

    for param in params:
        if param not in query_params:
            query_params[param] = [default_param_value or "testvalue"]

    new_query = urlencode(query_params, doseq=True)

    return urlunparse(parsed_url._replace(query=new_query))
