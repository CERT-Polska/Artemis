import asyncio
import dataclasses
from typing import Dict, List, Union

import aiohttp


@dataclasses.dataclass
class HTTPResponse:
    status_code: int
    content: str


async def _download(url, task_limitter) -> Union[HTTPResponse, Exception]:
    try:
        async with task_limitter:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, allow_redirects=False, timeout=5, ssl=False) as response:
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
