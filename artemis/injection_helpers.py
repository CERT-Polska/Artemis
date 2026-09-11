import json
from difflib import SequenceMatcher
from typing import Any

from artemis.http_requests import HTTPResponse


def responses_differ(response_a: HTTPResponse | None, response_b: HTTPResponse | None, threshold: float = 0.9) -> bool:
    # A missing response or a 5xx counts as "not different": a server error is noise (e.g. the server
    # crashing on an unexpected parameter), not evidence.
    if response_a is None or response_b is None:
        return False
    if response_a.status_code >= 500 or response_b.status_code >= 500:
        return False
    return SequenceMatcher(None, response_a.content, response_b.content).quick_ratio() < threshold


def create_status_reason(message: list[dict[str, Any]]) -> str:
    return ", ".join(sorted({f"{item.get('url')}: {item.get('statement')}" for item in message}))


def deduplicate_findings(message: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Serializing with sorted keys gives a stable identity for dicts built in a different key order.
    seen: set[str] = set()
    deduplicated: list[dict[str, Any]] = []
    for item in message:
        item_json = json.dumps(item, sort_keys=True)
        if item_json not in seen:
            seen.add(item_json)
            deduplicated.append(item)
    return deduplicated


def build_result_data(message: list[dict[str, Any]], statements: dict[str, str], **extra: Any) -> dict[str, Any]:
    # The envelope every injection detector saves; `extra` carries detector-specific keys.
    return {"result": deduplicate_findings(message), **extra, "statements": statements}
