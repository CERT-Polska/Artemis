import asyncio
from typing import Dict, List

import aiohttp


class HTTPResponse:
    status_code: int
    response: bytes
    content: str


async def download(url, task_limitter):
    async with task_limitter:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, allow_redirects=False, timeout=5, verify_ssl=False) as response:
                return HTTPResponse(
                    status_code=response.status_code, content=await response.text().decode("utf-8", errors="ignore")
                )


async def download_multiple(urls: List[str], max_parallel_tasks: int) -> Dict[str, HTTPResponse]:
    task_limitter = asyncio.BoundedSemaphore(max_parallel_tasks)
    jobs = []
    for url in urls:
        jobs.append(asyncio.ensure_future(download(url, task_limitter)))
    return dict(zip(urls, await asyncio.gather(*jobs)))


def download_urls(urls: List[str], max_parallel_tasks: int = 20) -> Dict[str, HTTPResponse]:
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(download_multiple(urls, max_parallel_tasks))
