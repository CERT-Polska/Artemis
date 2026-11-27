from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from artemis.modules.subdomain_enumeration import SubdomainEnumeration
from artemis.resolvers import ResolutionException

WILDCARD_IPS = {"192.0.2.1"}


def _run_filter(subdomains: set[str], dns_results: dict[str, set[str]]) -> set[str]:
    with patch("artemis.modules.subdomain_enumeration.lookup") as mock_lookup:

        def _lookup(domain: str) -> set[str]:
            if domain not in dns_results:
                raise ResolutionException(f"no result for {domain}")
            return dns_results[domain]

        mock_lookup.side_effect = _lookup
        stub = SimpleNamespace(log=MagicMock())
        return SubdomainEnumeration._filter_wildcard_subdomains(stub, WILDCARD_IPS, subdomains, "example.com")  # type: ignore[arg-type]


def test_www_subdomain_is_kept_when_everything_resolves_to_wildcard_ips() -> None:
    # All subdomains resolve only to wildcard IPs, so all are filtered out - but the
    # www subdomain should be kept as the single representative of the wildcard config.
    subdomains = {"api.example.com", "www.example.com"}
    dns_results = {subdomain: set(WILDCARD_IPS) for subdomain in subdomains}

    result = _run_filter(subdomains, dns_results)

    assert result == {"www.example.com"}


def test_first_subdomain_alphabetically_is_kept_when_no_www() -> None:
    subdomains = {"b.example.com", "a.example.com"}
    dns_results = {subdomain: set(WILDCARD_IPS) for subdomain in subdomains}

    result = _run_filter(subdomains, dns_results)

    assert result == {"a.example.com"}


def test_subdomains_with_non_wildcard_ips_are_kept() -> None:
    subdomains = {"api.example.com", "www.example.com"}
    dns_results = {
        "api.example.com": {"203.0.113.5"},
        "www.example.com": set(WILDCARD_IPS),
    }

    result = _run_filter(subdomains, dns_results)

    # api.example.com has non-wildcard IPs, so it is kept. www.example.com resolved only to
    # wildcard IPs, so it is filtered out - but it is re-added as the representative of the
    # wildcard config.
    assert result == {"api.example.com", "www.example.com"}


def test_unresolvable_subdomains_are_filtered_out_but_www_is_kept() -> None:
    # www.example.com no longer resolves (lookup raises ResolutionException), so it gets
    # filtered out - the www-keep fallback should still keep it as the representative.
    subdomains = {"www.example.com"}
    dns_results: dict[str, set[str]] = {}

    result = _run_filter(subdomains, dns_results)

    assert result == {"www.example.com"}


def test_nothing_is_kept_from_an_empty_subdomain_set() -> None:
    result = _run_filter(set(), {})

    assert result == set()
