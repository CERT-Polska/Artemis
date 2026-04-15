import json
from typing import Any, Dict, List, Optional

import requests
from packaging.version import InvalidVersion
from packaging.version import Version as PkgVersion
from redis import Redis

from artemis import utils
from artemis.config import Config
from artemis.redis_cache import RedisCache
from artemis.resource_lock import ResourceLock

logger = utils.build_logger(__name__)

WORDFENCE_PRODUCTION_FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"

# In-memory index built once per process lifetime: slug -> list of vuln entries
_WORDFENCE_INDEX: Optional[Dict[str, List[Dict[str, Any]]]] = None
REDIS = Redis.from_url(Config.Data.REDIS_CONN_STR)


def _build_index(feed: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}
    for vuln in feed.values():
        for software in vuln.get("software", []):
            slug = software.get("slug")
            if not slug:
                continue
            index.setdefault(slug, []).append(
                {
                    "id": vuln.get("id", ""),
                    "title": vuln.get("title", ""),
                    "cve": vuln.get("cve", None),
                    "copyrights": vuln.get("copyrights", None),
                    "cvss": (vuln.get("cvss") or {}).get("score", None),
                    "affected_versions": software.get("affected_versions", {}),
                    "patched_versions": vuln.get("patched_versions", []),
                }
            )
    return index


def _get_index() -> Dict[str, List[Dict[str, Any]]]:
    global _WORDFENCE_INDEX
    if _WORDFENCE_INDEX is None:
        lock = ResourceLock("wordfence_index")
        with lock:
            cache = RedisCache(REDIS, "wordfence_index", duration=6 * 60 * 60)
            if cache.get("data"):
                logger.info("Geting cached WordFence vulnerability feed")
            else:
                logger.info("Fetching WordFence vulnerability feed from %s", WORDFENCE_PRODUCTION_FEED_URL)
                response = requests.get(
                    WORDFENCE_PRODUCTION_FEED_URL,
                    headers={"Authorization": "Bearer " + Config.Modules.WordPressPlugins.WORDFENCE_API_KEY},
                )
                if errors := response.json().get("errors", None):
                    logger.info("Unable to retrieve WordFence vulnerability feed. Errors: %s", errors)
                    return {}
                cache.set("data", response.content)
             
            data = cache.get("data")
            assert data is not None
            _WORDFENCE_INDEX = _build_index(json.loads(data))
        logger.info("WordFence index built: %d plugin entries", len(_WORDFENCE_INDEX))
    return _WORDFENCE_INDEX


def _parse_version(v: str) -> Optional[PkgVersion]:
    try:
        return PkgVersion(v)
    except InvalidVersion:
        return None


def _is_version_in_range(version: str, affected_versions: Dict[str, Any]) -> bool:
    """Returns True if version falls within any of the affected version ranges."""
    parsed = _parse_version(version)
    if parsed is None:
        return False

    for range_def in affected_versions.values():
        from_ver = range_def.get("from_version", "*")
        to_ver = range_def.get("to_version", "*")
        from_inclusive = range_def.get("from_inclusive", True)
        to_inclusive = range_def.get("to_inclusive", True)

        # Check lower bound
        if from_ver != "*":
            parsed_from = _parse_version(from_ver)
            if parsed_from is None:
                continue
            if from_inclusive and parsed < parsed_from:
                continue
            if not from_inclusive and parsed <= parsed_from:
                continue

        # Check upper bound
        if to_ver != "*":
            parsed_to = _parse_version(to_ver)
            if parsed_to is None:
                continue
            if to_inclusive and parsed > parsed_to:
                continue
            if not to_inclusive and parsed >= parsed_to:
                continue

        return True

    return False


def get_vulnerabilities_for_plugin(slug: str, version: str) -> List[Dict[str, Any]]:
    """
    Returns WordFence vulnerabilities affecting the given plugin slug and version.

    Each returned entry contains:
        id            - WordFence UUID
        title         - vulnerability title
        cve           - CVE identifier or None
        cvss          - CVSS v3 score (float) or None
        patched_versions - list of versions that fix the vulnerability
    """
    index = _get_index()
    result = []
    for vuln in index.get(slug, []):
        if _is_version_in_range(version, vuln["affected_versions"]):
            result.append(
                {
                    "id": vuln["id"],
                    "title": vuln["title"],
                    "cve": vuln["cve"],
                    "cvss": vuln["cvss"],
                    "copyrights": vuln["copyrights"],
                    "patched_versions": vuln["patched_versions"],
                }
            )
    return result
