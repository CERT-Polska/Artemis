import asyncio
from typing import Optional

from artemis.config import Config
from artemis.resource_lock import AsyncResourceLock

IP_REQUEST_LOCK_KEY_PREFIX = "ip-request-lock-"


async def async_limit_requests_for_the_same_ip(ip: Optional[str]) -> None:
    if ip is None:
        ip = "unknown-ip"

    # Therefore we make sure no more than one request for this host will happen in the
    # next Config.SECONDS_PER_REQUEST_FOR_ONE_IP seconds
    await AsyncResourceLock(redis=Config.ASYNC_REDIS, res_name=IP_REQUEST_LOCK_KEY_PREFIX + ip).acquire(
        expiry=Config.SECONDS_PER_REQUEST_FOR_ONE_IP
    )


def limit_requests_for_the_same_ip(ip: Optional[str]) -> None:
    asyncio.run(async_limit_requests_for_the_same_ip(ip))
