import logging
import subprocess
import time
import urllib.parse
from ipaddress import ip_address
from typing import Any, Callable, List, Optional

from whoisdomain import Domain, WhoisQuotaExceeded  # type: ignore
from whoisdomain import query as whois_query

from artemis.config import Config


def check_output_log_on_error(command: List[str], logger: logging.Logger, **kwargs: Any) -> bytes:
    try:
        return subprocess.check_output(command, stderr=subprocess.PIPE, **kwargs)  # type: ignore
    except subprocess.CalledProcessError as e:
        logger.error(
            "Error when running %s: output=%s error=%s",
            command,
            e.stdout.decode("ascii", errors="ignore"),
            e.stderr.decode("ascii", errors="ignore"),
        )
        raise


def perform_whois_or_sleep(domain: str, logger: logging.Logger) -> Optional[Domain]:
    try:
        domain_data = whois_query(domain=domain)
        logger.info(
            "Successful whois query for %s expiry=%s", domain, domain_data.expiration_date if domain_data else None
        )
    except WhoisQuotaExceeded:
        logger.info("Quota exceeded for whois query for %s, sleeping 24 hours", domain)
        time.sleep(24 * 60 * 60)
        domain_data = whois_query(domain=domain)
        logger.info(
            "Successful whois query for %s after retry expiry=%s",
            domain,
            domain_data.expiration_date if domain_data else None,
        )
    return domain_data


def build_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


def is_directory_index(content: str) -> bool:
    if "directory listing denied" in content.lower():
        return False

    return (
        "Index of /" in content
        or "ListBucketResult" in content
        or "<title>directory listing" in content.lower()
        or "<title>index of" in content.lower()
    )


def throttle_request(f: Callable[[], Any]) -> Any:
    time_start = time.time()
    try:
        return f()
    finally:
        time_elapsed = time.time() - time_start
        if time_elapsed < Config.Limits.SECONDS_PER_REQUEST:
            time.sleep(Config.Limits.SECONDS_PER_REQUEST - time_elapsed)


def get_host_from_url(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    assert host is not None
    return host


def is_ip_address(host: str) -> bool:
    try:
        # if this doesn't throw then we have an IP address
        ip_address(host)
        return True
    except ValueError:
        return False
