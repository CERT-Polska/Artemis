import random
import re
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Type
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

from karton.core import Task

from artemis.binds import TaskStatus
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS

if TYPE_CHECKING:
    from artemis.db import DB


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


def change_url_params(url: str, payload: str, param_batch: Sequence[str]) -> str:
    """Replace existing URL query parameters and append batch parameters with the given payload.

    Modifies all existing query parameters in the URL to the given payload and
    appends additional parameters from param_batch.
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    new_query_params = {}
    assignments = {key: payload for key in param_batch}

    for param in query_params:
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
    concatenation = "&" if is_url_with_parameters(new_url) else "?"
    new_url = f"{new_url}" + concatenation + "&".join([f"{key}={value}" for key, value in assignments.items()])
    return unquote(new_url)


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


def create_status_reason(messages: List[Dict[str, Any]]) -> Optional[str]:
    """Build a status reason string from scan result messages.

    If a message's statement already contains the URL, it is used as-is.
    Otherwise, the URL is prepended in the format 'url: statement'.
    """
    if not messages:
        return None
    status_reasons = set()
    for m in messages:
        url = m.get("url", "")
        statement = m.get("statement", "")
        if url and url not in statement:
            status_reasons.add(f"{url}: {statement}")
        else:
            status_reasons.add(statement)
    return ", ".join(status_reasons)


def create_scan_result_data(messages: List[Dict[str, Any]], statements_enum: Type[Enum]) -> Dict[str, Any]:
    """Create the standard data dict for injection scan results."""
    return {
        "result": messages,
        "statements": {e.value: e.name for e in statements_enum},
    }


def process_and_save_scan_results(
    messages: List[Dict[str, Any]],
    statements_enum: Type[Enum],
    task: Task,
    db: "DB",
) -> None:
    """Process scan results and save them to the database.

    Determines the task status based on whether vulnerabilities were found,
    creates the status reason and result data, and saves to the database.
    """
    if messages:
        status = TaskStatus.INTERESTING
        status_reason = create_status_reason(messages)
    else:
        status = TaskStatus.OK
        status_reason = None

    data = create_scan_result_data(messages, statements_enum)
    db.save_task_result(task=task, status=status, status_reason=status_reason, data=data)
