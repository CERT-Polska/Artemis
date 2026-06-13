import functools
import hashlib
import json
import subprocess
from typing import List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from bs4.exceptions import ParserRejectedMarkup  # type: ignore
from redis import Redis

from artemis import http_requests, utils
from artemis.config import Config
from artemis.redis_cache import RedisCache
from artemis.resource_lock import FailedToAcquireLockException, ResourceLock

logger = utils.build_logger(__name__)

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_CDX_LIMIT = 5000

_REDIS = Redis.from_url(Config.Data.REDIS_CONN_STR)
_CRAWL_CACHE = RedisCache(_REDIS, "crawl_pipeline", duration=Config.Modules.Crawling.CRAWL_CACHE_TTL_SECONDS)


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
        html_params = list(_fetch_injectable_parameters(url))
    except Exception:
        html_params = []

    try:
        wayback_params = get_wayback_parameters(url)
    except Exception:
        wayback_params = []

    return list(set(html_params + wayback_params))


@functools.lru_cache(maxsize=1024)
def _fetch_wayback_parameters(domain: str) -> Tuple[str, ...]:
    response = requests.get(
        WAYBACK_CDX_URL,
        params={
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(WAYBACK_CDX_LIMIT),
        },
        timeout=30,
    )
    response.raise_for_status()
    rows = response.json()

    params: set[str] = set()
    for row in rows[1:]:  # skip header row
        try:
            parsed = urlparse(row[0])
            params.update(parse_qs(parsed.query).keys())
        except IndexError:
            continue
    return tuple(params)


def get_wayback_parameters(url: str) -> List[str]:
    domain = urlparse(url).hostname
    if not domain:
        return []
    try:
        return list(_fetch_wayback_parameters(domain))
    except Exception:
        logger.exception("Failed to fetch Wayback CDX data for %s", domain)
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


def _normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
        port = None
    netloc = f"{host}:{port}" if port else host
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", "", ""))


def _cache_key(normalized_url: str) -> str:
    # KATANA_TIMEOUT_SECONDS is excluded: changing the timeout must not invalidate cached results.
    parts = [
        normalized_url,
        str(Config.Modules.Crawling.KATANA_DEPTH),
        str(Config.Modules.Crawling.KATANA_MAX_URLS),
        Config.Miscellaneous.CUSTOM_USER_AGENT or "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _run_katana_uro(normalized_url: str) -> Tuple[List[str], bool]:
    katana_args = [
        "katana",
        "-u",
        normalized_url,
        "-d",
        str(Config.Modules.Crawling.KATANA_DEPTH),
        "-jsonl",
        "-jc",
        "-field-scope",
        "dn",
        # If we limit the number of URLs to obtain, let's crawl it using BFS,
        # so that we broadly crawl all features of the website instead of focusing
        # on the first.
        "-strategy",
        "breadth-first",
        "-c",
        str(Config.Modules.Crawling.KATANA_CONCURRENCY),
        "-mdp",
        str(Config.Modules.Crawling.KATANA_MAX_URLS),
        "-silent",
    ]
    if Config.Limits.REQUESTS_PER_SECOND:
        katana_args.extend(["-rate-limit", str(int(Config.Limits.REQUESTS_PER_SECOND))])

    if Config.Miscellaneous.CUSTOM_USER_AGENT:
        katana_args.extend(["-H", f"User-Agent: {Config.Miscellaneous.CUSTOM_USER_AGENT}"])

    timeout_s = Config.Modules.Crawling.KATANA_TIMEOUT_SECONDS
    partial = False
    proc = subprocess.Popen(katana_args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        katana_stdout, _ = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        katana_stdout, _ = proc.communicate()
        partial = True
        logger.warning("Katana timed out after %ss for %s", timeout_s, normalized_url)

    raw_urls: List[str] = []
    for line in katana_stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        request = entry.get("request") if isinstance(entry, dict) else None
        url = request.get("endpoint") if isinstance(request, dict) else None
        if isinstance(url, str) and url:
            raw_urls.append(url)

    try:
        result = subprocess.run(["uro"], input="\n".join(raw_urls).encode(), capture_output=True, timeout=60)
        deduped = [u for u in result.stdout.decode().splitlines() if u]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        deduped = list(set(raw_urls))

    target_host = urlparse(normalized_url).hostname
    deduped = [u for u in deduped if urlparse(u).hostname == target_host]
    return deduped, partial


def crawl_and_filter(url: str) -> List[str]:
    normalized = _normalize_url(url)
    key = _cache_key(normalized)

    deduped: List[str]

    cached = _CRAWL_CACHE.get(f"raw:{key}")
    if cached:
        deduped = json.loads(cached)
    else:
        lock = ResourceLock(f"crawl-lock-{key}", max_tries=1)
        try:
            lock.acquire()
        except FailedToAcquireLockException:
            deduped, _ = _run_katana_uro(normalized)
        else:
            try:
                cached = _CRAWL_CACHE.get(f"raw:{key}")
                if cached:
                    deduped = json.loads(cached)
                else:
                    deduped, partial = _run_katana_uro(normalized)
                    ttl = (
                        Config.Modules.Crawling.KATANA_TIMEOUT_CACHE_TTL_SECONDS
                        if partial
                        else Config.Modules.Crawling.CRAWL_CACHE_TTL_SECONDS
                    )
                    _CRAWL_CACHE.set(f"raw:{key}", json.dumps(deduped).encode(), timeout=ttl)
            finally:
                lock.release()

    return list(deduped)
