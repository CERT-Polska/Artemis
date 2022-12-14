import asyncio
import dataclasses
import urllib.parse
from typing import Dict, List, Optional, Union

import aiohttp
import requests

from artemis.config import Config
from artemis.request_limit import (
    UnknownIPException,
    async_limit_requests_for_ip,
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


def _request(
    method_name: str, url: str, allow_redirects: bool, data: Optional[Dict[str, str]], cookies: Optional[Dict[str, str]]
) -> requests.Response:
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
    assert isinstance(response, requests.Response)
    return response


def get(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> requests.Response:
    return _request("get", url, allow_redirects, data, cookies)


def post(
    url: str,
    allow_redirects: bool = True,
    data: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> requests.Response:
    return _request("post", url, allow_redirects, data, cookies)


@dataclasses.dataclass
class HTTPResponse:
    status_code: int
    content: str


async def _download(url: str, task_limitter: asyncio.BoundedSemaphore) -> Union[HTTPResponse, Exception]:
    try:
        async with task_limitter:
            await async_limit_requests_for_ip(url_to_ip(url))

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, allow_redirects=False, timeout=Config.HTTP_TIMEOUT_SECONDS, ssl=False, headers=HEADERS
                ) as response:
                    response_bytes = await response.read()
                    response_str = response_bytes.decode(response.charset or "utf-8", errors="ignore")
                    return HTTPResponse(status_code=response.status, content=response_str)
    except Exception as e:
        return e


async def _download_urls_async(urls: List[str], max_parallel_tasks: int) -> Dict[str, HTTPResponse]:
    task_limitter = asyncio.BoundedSemaphore(max_parallel_tasks)
    jobs = []
    for url in urls:
        jobs.append(asyncio.ensure_future(_download(url, task_limitter)))

    result = {}
    for url, response in zip(urls, await asyncio.gather(*jobs)):
        if isinstance(response, Exception):
            continue
        result[url] = response
    return result


def download_urls(urls: List[str], max_parallel_tasks: int = Config.MAX_ASYNC_PER_LOOP) -> Dict[str, HTTPResponse]:
    """
    Downloads URLs from the list and returns a dict: url -> response. If a download resulted in an
    exception, no entry will be provided.
    """
    with asyncio.Runner() as runner:
        return runner.run(_download_urls_async(urls, max_parallel_tasks))
