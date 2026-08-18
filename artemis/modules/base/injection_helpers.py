import json
from difflib import SequenceMatcher
from typing import Any

from artemis.http_requests import HTTPResponse


def responses_differ(response_a: HTTPResponse | None, response_b: HTTPResponse | None, threshold: float = 0.9) -> bool:
    # True when two responses are meaningfully different. A missing response, or a 5xx on either side,
    # counts as "not different" - a server error is noise (e.g. the server crashing on an unexpected
    # parameter), not evidence - so the text similarity is only compared when both sides are usable.
    if response_a is None or response_b is None:
        return False
    if response_a.status_code >= 500 or response_b.status_code >= 500:
        return False
    return SequenceMatcher(None, response_a.content, response_b.content).quick_ratio() < threshold


def create_status_reason(message: list[dict[str, Any]]) -> str:
    # Stable, deduplicated "<url>: <statement>" summary of the findings.
    return ", ".join(sorted({f"{item.get('url')}: {item.get('statement')}" for item in message}))


def deduplicate_findings(message: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Drop exact-duplicate findings while keeping first-seen order. Serializing with sorted keys
    # gives a stable identity for dicts whose keys were built in a different order.
    seen: set[str] = set()
    deduplicated: list[dict[str, Any]] = []
    for item in message:
        item_json = json.dumps(item, sort_keys=True)
        if item_json not in seen:
            seen.add(item_json)
            deduplicated.append(item)
    return deduplicated


def build_result_data(message: list[dict[str, Any]], statements: dict[str, str], **extra: Any) -> dict[str, Any]:
    # The result envelope every injection detector saves: the deduplicated findings, the map of
    # statement codes the reporter reads, and any detector-specific extra keys (e.g. untestable_urls).
    return {"result": deduplicate_findings(message), **extra, "statements": statements}
