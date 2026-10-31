from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from artemis.config import Config
from artemis.modules.subdomain_enumeration import SubdomainEnumeration


@patch.object(Config.Limits, "SHARED_IP_RPS_NUM_DOMAINS_THRESHOLD", 2)
@patch("artemis.modules.subdomain_enumeration.lookup")
def test_get_domains_on_shared_ip_uses_each_dns_result_once(mock_lookup: MagicMock) -> None:
    dns_results = {
        "a.shared.com": {"192.0.2.1"},
        "b.shared.com": {"192.0.2.1", "192.0.2.2"},
        "c.shared.com": {"192.0.2.2"},
        "alone.com": {"192.0.2.3"},
    }
    mock_lookup.side_effect = dns_results.__getitem__
    stub = SimpleNamespace(log=MagicMock())

    result = SubdomainEnumeration.get_domains_on_shared_ip(stub, set(dns_results))  # type: ignore

    assert result == {"a.shared.com", "b.shared.com", "c.shared.com"}


@patch.object(Config.Limits, "SHARED_IP_RPS_NUM_DOMAINS_THRESHOLD", 0)
@patch("artemis.modules.subdomain_enumeration.lookup")
def test_get_domains_on_shared_ip_skips_dns_when_disabled(mock_lookup: MagicMock) -> None:
    dns_results = {
        "a.shared.com": {"192.0.2.1"},
        "b.shared.com": {"192.0.2.1", "192.0.2.2"},
        "c.shared.com": {"192.0.2.2"},
        "alone.com": {"192.0.2.3"},
    }
    mock_lookup.side_effect = dns_results.__getitem__
    stub = SimpleNamespace(log=MagicMock())

    result = SubdomainEnumeration.get_domains_on_shared_ip(stub, set(dns_results))  # type: ignore

    assert result == set()
    mock_lookup.assert_not_called()
