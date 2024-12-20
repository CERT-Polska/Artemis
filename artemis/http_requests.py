import copy
import dataclasses
import json
import os
import ssl
import urllib.parse
from typing import Any, Dict, Optional

import chardet
import requests

from artemis.config import Config
from artemis.utils import build_logger, throttle_request

LOGGER = build_logger(__name__)


# As our goal in Artemis is to access the sites in order to test their security, let's
# enable SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION in order to make a connection even if it's
# not secure.
class SSLContextAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):  # type: ignore
        context = ssl.create_default_context()

        SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 1 << 18

        context.check_hostname = False
        context.options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION

        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)  # type: ignore


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
    headers: Dict[str, str]

    def json(self) -> Any:
        return json.loads(self.content)

    @property
    def text(self) -> str:
        return self.content

    @property
    def content(self) -> str:
        if self.encoding:
            return self.content_bytes.decode(self.encoding, errors="ignore")
        else:
            encoding = chardet.detect(self.content_bytes)["encoding"] or "utf-8"
            return self.content_bytes.decode(encoding, errors="ignore")


def _request(
    method_name: str,
    url: str,
    allow_redirects: bool,
    data: Optional[Dict[str, str]],
    cookies: Optional[Dict[str, str]],
    max_size: int = Config.Miscellaneous.CONTENT_PREFIX_SIZE,
    requests_per_second: float = Config.Limits.REQUESTS_PER_SECOND,
    **kwargs: Any,
) -> HTTPResponse:
    if "RUNNING_TESTS" in os.environ:
        # The de facto limit is 2000 according to
        # https://stackoverflow.com/questions/417142/what-is-the-maximum-length-of-a-url-in-different-browsers
        # so let's check something lower to make sure our modules aren't exceeding the limit e.g.
        # when batching parameters for SQL injection check.
        assert len(url) < 1600, f"URL too long, has {len(url)} characters"

    def _internal_request() -> HTTPResponse:
        headers = copy.copy(HEADERS)
        headers.update(kwargs["headers"]) if "headers" in kwargs else headers

        s = requests.Session()
        url_parsed = urllib.parse.urlparse(url)
        if url_parsed.scheme.lower() == "https":
            s.mount(url, SSLContextAdapter())

        if url_parsed.username or url_parsed.password:
            LOGGER.debug(
                "%s %s",
                method_name,
                urllib.parse.urlunparse(url_parsed._replace(netloc="***:***@" + (url_parsed.hostname or ""))),
            )
        else:
            LOGGER.debug("%s %s", method_name, url)

        response = getattr(s, method_name)(
            url,
            allow_redirects=allow_redirects,
            data=data,
            cookies=cookies,
            verify=False,
            stream=True,
            timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS,
            headers=headers,
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
            headers=response.headers,
        )

    return throttle_request(_internal_request, requests_per_second)  # type: ignore


def get(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    requests_per_second: float = Config.Limits.REQUESTS_PER_SECOND,
    **kwargs: Any,
) -> HTTPResponse:
    return _request("get", url, allow_redirects, data, cookies, requests_per_second=requests_per_second, **kwargs)


def post(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    requests_per_second: float = Config.Limits.REQUESTS_PER_SECOND,
    **kwargs: Any,
) -> HTTPResponse:
    return _request("post", url, allow_redirects, data, cookies, requests_per_second=requests_per_second, **kwargs)
