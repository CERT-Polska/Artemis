import dataclasses
import json
from typing import Any, Dict, Optional

import requests

from artemis.config import Config
from artemis.utils import throttle_request

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)  # type: ignore

if Config.Miscellaneous.CUSTOM_USER_AGENT:
    HEADERS = {"User-Agent": Config.Miscellaneous.CUSTOM_USER_AGENT}
else:
    HEADERS = {}


# We create a simple response class that is just a container for a status code and decoded
# string, without any streaming capabilities - returning a Response would require us to implement
# more.
@dataclasses.dataclass
class HTTPResponse:
    status_code: int
    content_bytes: bytes
    encoding: str
    is_redirect: bool
    url: str

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def text(self) -> str:
        return self.content

    @property
    def content(self) -> str:
        return self.content_bytes.decode(self.encoding or "utf-8", errors="ignore")


def _request(
    method_name: str,
    url: str,
    allow_redirects: bool,
    data: Optional[Dict[str, str]],
    cookies: Optional[Dict[str, str]],
    max_size: int = Config.Miscellaneous.CONTENT_PREFIX_SIZE,
) -> HTTPResponse:
    def _internal_request() -> HTTPResponse:
        response = getattr(requests, method_name)(
            url,
            allow_redirects=allow_redirects,
            data=data,
            cookies=cookies,
            verify=False,
            stream=True,
            timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS,
            headers=HEADERS,
        )

        # Handling situations where the response is very long, which is not handled by requests timeout
        result = b""
        # Sometimes the returned chunks are significantly shorter than max_size, therefore we iterate until
        # we run out of chunks or we complete a result of expected size.
        for item in response.iter_content(max_size):
            result += item

            if len(result) >= max_size:
                break

        return HTTPResponse(
            status_code=response.status_code,
            content_bytes=result[:max_size],
            encoding=response.encoding if response.encoding else "utf-8",
            is_redirect=bool(response.history),
            url=response.url,
        )

    return throttle_request(_internal_request)  # type: ignore


def get(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    **kwargs: Any
) -> HTTPResponse:
    return _request("get", url, allow_redirects, data, cookies, **kwargs)


def post(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    **kwargs: Any
) -> HTTPResponse:
    return _request("post", url, allow_redirects, data, cookies, **kwargs)
