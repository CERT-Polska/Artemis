from types import SimpleNamespace
from typing import List, Optional, Set
from unittest.mock import MagicMock

from artemis.modules.subdomain_enumeration import SubdomainEnumeration


def stub_with_tool_results(results: List[Optional[Set[str]]]) -> SimpleNamespace:
    remaining = list(results)
    return SimpleNamespace(
        log=MagicMock(),
        get_subdomains_from_tool=lambda *args, **kwargs: remaining.pop(0),
    )


def test_subfinder_reports_failure_when_both_runs_fail() -> None:
    stub = stub_with_tool_results([None, None])
    assert SubdomainEnumeration.get_subdomains_from_subfinder(stub, "example.com") is None


def test_subfinder_keeps_the_results_of_the_run_that_worked() -> None:
    stub = stub_with_tool_results([None, {"a.example.com"}])
    assert SubdomainEnumeration.get_subdomains_from_subfinder(stub, "example.com") == {"a.example.com"}


def test_subfinder_returns_an_empty_set_when_both_runs_find_nothing() -> None:
    stub = stub_with_tool_results([set(), set()])
    assert SubdomainEnumeration.get_subdomains_from_subfinder(stub, "example.com") == set()
