import random
from ipaddress import ip_address

from artemis.config import Config
from artemis.resolvers import ip_lookup
from artemis.resource_lock import ResourceLock

IP_REQUEST_LOCK_KEY_PREFIX = "ip-request-lock-"


class UnknownIPException(Exception):
    pass


def limit_requests_for_ip(ip: str) -> None:
    # Therefore we make sure no more than one request for this host will happen in the
    # next Config.SECONDS_PER_REQUEST_FOR_ONE_IP seconds
    ResourceLock(redis=Config.REDIS, res_name=IP_REQUEST_LOCK_KEY_PREFIX + ip).acquire(
        expiry=Config.SECONDS_PER_REQUEST_FOR_ONE_IP
    )


def get_ip_for_locking(host: str) -> str:
    try:
        # if this doesn't throw then we have an IP address
        ip_address(host)
        return host
    except ValueError:
        pass

    # Here, we use the the DoH resolvers so that we don't leak information if using proxies.
    # There is a chance that the IP returned here (chosen randomly from a set of IP adresses)
    # would be different from the one chosen for the actual connection - but we hope that over
    # time and across multiple scanner instances the overall load would be approximately similar
    # to one request per Config.SECONDS_PER_REQUEST_FOR_ONE_IP.
    ip_addresses = list(ip_lookup(host))

    if not ip_addresses:
        raise UnknownIPException(f"Unknown IP for host {host}")

    return random.choice(ip_addresses)


def limit_requests_for_host(host: str) -> None:
    limit_requests_for_ip(get_ip_for_locking(host))
