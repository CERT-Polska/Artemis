import asyncio
import dataclasses
from typing import Dict, List

import aiohttp


@dataclasses.dataclass
class HTTPResponse:
    status_code: int
    content: str


async def download(url, task_limitter):
    async with task_limitter:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=False, timeout=5, ssl=False) as response:
                return HTTPResponse(status_code=response.status, content=await response.text())


async def _download_urls_async(urls: List[str], max_parallel_tasks: int) -> Dict[str, HTTPResponse]:
    task_limitter = asyncio.BoundedSemaphore(max_parallel_tasks)
    jobs = []
    for url in urls:
        jobs.append(asyncio.ensure_future(download(url, task_limitter)))
    return dict(zip(urls, await asyncio.gather(*jobs)))


def download_urls(urls: List[str], max_parallel_tasks: int = 20) -> Dict[str, HTTPResponse]:
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_download_urls_async(urls, max_parallel_tasks))
