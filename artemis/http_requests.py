import dataclasses
import json
import urllib.parse
from typing import Any, Dict, Optional

import requests

from artemis.config import Config
from artemis.request_limit import (
    UnknownIPException,
    get_ip_for_locking,
    limit_requests_for_ip,
)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)  # type: ignore

if Config.CUSTOM_USER_AGENT:
    HEADERS = {"User-Agent": Config.CUSTOM_USER_AGENT}
else:
    HEADERS = {}


def url_to_ip(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname

    if not host:
        raise UnknownIPException(f"Unknown host for URL: {url}")

    return get_ip_for_locking(host)


@dataclasses.dataclass
class HTTPResponse:
    status_code: int
    content: str

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def text(self) -> str:
        return self.content


def _request(
    method_name: str,
    url: str,
    allow_redirects: bool,
    data: Optional[Dict[str, str]],
    cookies: Optional[Dict[str, str]],
    max_size: int = 100_000,
) -> HTTPResponse:
    limit_requests_for_ip(url_to_ip(url))

    response = getattr(requests, method_name)(
        url,
        allow_redirects=allow_redirects,
        data=data,
        cookies=cookies,
        verify=False,
        timeout=Config.HTTP_TIMEOUT_SECONDS,
        headers=HEADERS,
    )

    # Handling situations where the response is very long, which is not handled by requests timeout
    for item in response.iter_content(max_size):
        return HTTPResponse(status_code=response.status_code, content=item.decode("utf-8", errors="ignore"))
    return HTTPResponse(status_code=response.status_code, content="")


def get(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> HTTPResponse:
    return _request("get", url, allow_redirects, data, cookies)


def post(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> HTTPResponse:
    return _request("post", url, allow_redirects, data, cookies)
