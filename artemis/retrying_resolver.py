# The recommended resolver in Artemis resided in artemis.resolvers and uses DoH. It is recommended
# in case later a decision is made to allow full proxying. In case some libraries (e.g. checkdmarc)
# don't use that resolver now, we also patch dns.resolver.

from typing import Any, Callable, Dict, Tuple

import dns.resolver

from artemis.config import Config
from artemis.utils import build_logger

logger = build_logger(__name__)


def retry(function: Callable[..., Any], function_args: Tuple[Any, ...], function_kwargs: Dict[str, Any]) -> Any:
    result = None
    last_exception = None
    num_exceptions = 0

    for _ in range(Config.Miscellaneous.NUM_DNS_RESOLVER_RETRIES):
        try:
            result = function(*function_args, **function_kwargs)
            break
        except Exception as e:
            num_exceptions += 1
            logger.exception("problem when resolving %s, %s", function_args, function_kwargs)
            last_exception = e

    flaky = num_exceptions > 0 and num_exceptions < Config.Miscellaneous.NUM_DNS_RESOLVER_RETRIES

    if flaky:
        logger.info(
            "flaky DNS query: %s, %s",
            function_args,
            function_kwargs,
        )

    if last_exception and not result:
        raise last_exception

    return result


class WrappedResolver(dns.resolver.Resolver):
    def resolve(self, *args, **kwargs):  # type: ignore
        return retry(super().resolve, args, kwargs)


def setup_retrying_resolver() -> None:
    if dns.resolver.Resolver != WrappedResolver:
        dns.resolver.Resolver = WrappedResolver  # type: ignore
