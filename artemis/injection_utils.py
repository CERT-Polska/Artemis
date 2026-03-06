import random
import re
from typing import List, Sequence
from urllib.parse import urlparse, urlunparse

from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS


def strip_query_string(url: str) -> str:
    """Strip query string and fragment from a URL."""
    url_parsed = urlparse(url)
    return urlunparse(url_parsed._replace(query="", fragment=""))


def is_url_with_parameters(url: str) -> bool:
    """Check if a URL contains query parameters."""
    return bool(re.search(r"/?/*=", url))


def create_url_with_batch_payload(url: str, param_batch: Sequence[str], payload: str) -> str:
    """Create a URL with multiple parameters set to the same payload value."""
    assignments = {key: payload for key in param_batch}
    concatenation = "&" if is_url_with_parameters(url) else "?"
    return f"{url}{concatenation}" + "&".join([f"{key}={value}" for key, value in assignments.items()])


def collect_urls_to_scan(url: str) -> List[str]:
    """Collect and prepare URLs for injection scanning from a base URL.

    Gathers links from the same domain, strips query strings to create additional
    URL variants, filters out static resources, shuffles for randomization, and
    limits to the configured maximum.
    """
    links = get_links_and_resources_on_same_domain(url)
    links.append(url)
    links = list(set(links) | set([strip_query_string(link) for link in links]))

    links = [
        link.split("#")[0]
        for link in links
        if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
    ]

    random.shuffle(links)
    return links[: Config.Miscellaneous.MAX_URLS_TO_SCAN]
