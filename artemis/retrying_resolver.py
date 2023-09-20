import dns.resolver

from artemis.config import Config
from artemis.utils import build_logger


class WrappedResolver(dns.resolver.Resolver):
    logger = build_logger(__name__)

    def resolve(self, *args, **kwargs):  # type: ignore
        result = None
        last_exception = None
        num_exceptions = 0

        for _ in range(Config.Miscellaneous.NUM_DNS_RESOLVER_RETRIES):
            try:
                result = super().resolve(*args, **kwargs)
                break
            except Exception as e:
                num_exceptions += 1
                self.logger.exception("problem when resolving: %s, %s", args, kwargs)
                last_exception = e

        self.logger.info(
            "%s DNS query: %s, %s",
            "flaky"
            if num_exceptions > 0 and num_exceptions < Config.Miscellaneous.NUM_DNS_RESOLVER_RETRIES
            else "non-flaky",
            args,
            kwargs,
        )

        if last_exception and not result:
            raise last_exception

        return result


def setup_retrying_resolver() -> None:
    if dns.resolver.Resolver != WrappedResolver:
        dns.resolver.Resolver = WrappedResolver  # type: ignore
