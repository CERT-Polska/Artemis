import asyncio
import dataclasses
from typing import Dict, List, Optional, Union

import aiohttp
import requests

from artemis.config import Config

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)  # type: ignore

TIMEOUT_SECONDS = 5

if Config.SCANNING_USER_AGENT_OVERRIDE:
    HEADERS = {"User-Agent": Config.SCANNING_USER_AGENT_OVERRIDE}
else:
    HEADERS = {}


def _request(
    method_name: str, url: str, allow_redirects: bool, data: Optional[Dict[str, str]], cookies: Optional[Dict[str, str]]
) -> requests.Response:
    response = getattr(requests, method_name)(
        url,
        allow_redirects=allow_redirects,
        data=data,
        cookies=cookies,
        verify=False,
        timeout=TIMEOUT_SECONDS,
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
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, allow_redirects=False, timeout=TIMEOUT_SECONDS, ssl=False, headers=HEADERS
                ) as response:
                    return HTTPResponse(status_code=response.status, content=await response.text())
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


def download_urls(urls: List[str], max_parallel_tasks: int = 5) -> Dict[str, HTTPResponse]:
    """
    Downloads URLs from the list and returns a dict: url -> response. If a download resulted in an
    exception, no entry will be provided.
    """
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_download_urls_async(urls, max_parallel_tasks))
