# The recommended resolver in Artemis resided in artemis.resolvers and uses DoH. It is recommended
# in case later a decision is made to allow full proxying. In case some libraries (e.g. checkdmarc)
# don't use that resolver now, we also patch dns.resolver.

import socket
from typing import Any, Callable, Dict, Tuple

import dns
import dns.flags
import dns.rdatatype
import dns.rdtypes.IN.A
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
    def resolve(self, qname, rdtype=dns.rdatatype.RdataType.A, *args, **kwargs):  # type: ignore
        if rdtype in ["A", dns.rdatatype.RdataType.A, "AAAA", dns.rdatatype.RdataType.AAAA]:
            try:
                qname_str = str(qname).rstrip(".")
                # First try socket.gethostbyname to lookup from hosts file

                host = socket.gethostbyname(qname_str)

                rdata = dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, host)  # type: ignore
                rrset = dns.rrset.from_rdata(qname_str, 300, rdata)
                response = dns.message.make_query(qname_str, dns.rdatatype.A, dns.rdataclass.IN)
                response.flags |= dns.flags.QR
                response.answer.append(rrset)
                answer = dns.resolver.Answer(qname, rdtype, dns.rdataclass.IN, response, "127.0.0.1", 53)
                answer.rrset = rrset
                return answer
            except socket.gaierror:
                pass

        return retry(super().resolve, (qname, rdtype) + tuple(args), kwargs)


def setup_retrying_resolver() -> None:
    if dns.resolver.Resolver != WrappedResolver:
        dns.resolver.Resolver = WrappedResolver  # type: ignore
