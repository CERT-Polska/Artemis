"""Optional source of previously discovered assets, supplementing local discovery."""

import random
import re

import requests
from karton.core.task import TaskPriority

from artemis.config import Config
from artemis.utils import build_logger

logger = build_logger(__name__)


def _get_regex_for_output_validation(endpoint: str) -> re.Pattern[str]:
    if endpoint == "get_subdomains":
        return re.compile(r"([a-zA-Z0-9-\.]+)", re.IGNORECASE)
    elif endpoint == "get_parameters":
        return re.compile(r"^[a-zA-Z0-9_.\-]{1,30}$")
    elif endpoint == "get_files":
        return re.compile(r"[a-z0-9-/._]+", re.IGNORECASE)
    elif endpoint == "get_admin_panel_urls":
        return re.compile(r"[a-z0-9-/._]+", re.IGNORECASE)
    else:
        raise NotImplementedError()


def is_output_line_correct(output_line: str, endpoint: str, max_length: int = 30) -> bool:
    pattern = _get_regex_for_output_validation(endpoint)
    return bool(output_line.strip() and len(output_line) < max_length and pattern.fullmatch(output_line.strip()))


def get_assets(priority: TaskPriority, endpoint: str, target: str, max_count: int = 200) -> list[str]:
    base_url = Config.ScannedAssetsAPI.SCANNED_ASSETS_API_URL
    if not base_url:
        return []

    assert endpoint in ["get_subdomains", "get_files", "get_parameters", "get_admin_panel_urls"]

    parameter = "domain" if endpoint == "get_subdomains" else "url"
    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/{endpoint}",
            params={parameter: target, "priority": str(priority)},
            timeout=300,  # Make the timeout large, it might need heavy queries
        )
        response.raise_for_status()
        assets = response.json()
        if not isinstance(assets, list) or not all(isinstance(asset, str) for asset in assets):
            raise ValueError("Expected a JSON array of strings")

        random.shuffle(assets)
        results = []
        for asset in assets[:max_count]:
            if is_output_line_correct(asset, endpoint):
                results.append(asset.strip())

        logger.info("Obtained additional assets for %s %s: %s", endpoint, target, results)

    except (requests.RequestException, ValueError):
        logger.warning("Unable to obtain assets from scanned asset API endpoint %s", endpoint, exc_info=True)
        return []

    return results
