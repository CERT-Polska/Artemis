import logging
import subprocess
import time
import urllib.parse
from ipaddress import ip_address
from typing import Any, Callable, List, Optional

from bs4 import BeautifulSoup
from whoisdomain import Domain, WhoisQuotaExceeded  # type: ignore
from whoisdomain import query as whois_query

from artemis import http_requests
from artemis.config import Config


class CalledProcessErrorWithMessage(subprocess.CalledProcessError):
    def __init__(self, message: str, returncode: int, cmd: List[str], output: bytes, stderr: bytes):
        super().__init__(returncode, cmd, output, stderr)
        self.message = message

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return self.message


def check_output_log_on_error(command: List[str], logger: logging.Logger, **kwargs: Any) -> bytes:
    try:
        return subprocess.check_output(command, stderr=subprocess.PIPE, **kwargs)  # type: ignore
    except subprocess.CalledProcessError as e:
        command_str_shortened = repr(command)
        if len(command_str_shortened) > 100:
            command_str_shortened = command_str_shortened[:100] + "..."

        message = 'Error when running "%s": output="%s" error="%s" original message="%s"' % (
            command_str_shortened,
            e.stdout.decode("ascii", errors="ignore"),
            e.stderr.decode("ascii", errors="ignore"),
            repr(e),
        )
        logger.error(message)
        raise CalledProcessErrorWithMessage(
            message=message, returncode=e.returncode, cmd=e.cmd, output=e.output, stderr=e.stderr
        )


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
    handler.setFormatter(logging.Formatter(Config.Miscellaneous.LOGGING_FORMAT_STRING))
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
    request_per_second = Config.Limits.REQUESTS_PER_SECOND
    if request_per_second == 0:
        return f()
    elif request_per_second > 0:
        average_time_per_request = 1 / request_per_second
        f_start = time.time()
        try:
            return f()
        finally:
            func_time = time.time() - f_start
            if func_time < average_time_per_request:
                time.sleep(average_time_per_request - func_time)


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


def get_links_and_resources_on_same_domain(url: str) -> List[str]:
    url_parsed = urllib.parse.urlparse(url)
    response = http_requests.get(url)
    soup = BeautifulSoup(response.text)
    links = []
    for tag in soup.find_all():
        new_url = None
        for attribute in ["src", "href"]:
            if attribute not in tag.attrs:
                continue

            new_url = urllib.parse.urljoin(url, tag[attribute])
            new_url_parsed = urllib.parse.urlparse(new_url)

            if url_parsed.netloc == new_url_parsed.netloc:
                links.append(new_url)
    return links
