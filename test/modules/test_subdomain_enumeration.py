from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.subdomain_enumeration import SubdomainEnumeration


class SubdomainEnumerationScannerTest(ArtemisModuleTestCase):
    karton_class = SubdomainEnumeration  # type: ignore

    @patch.object(SubdomainEnumeration, "get_subdomains_by_dns_brute_force", return_value=set())
    @patch.object(SubdomainEnumeration, "get_subdomains_from_gau", return_value=set())
    @patch.object(SubdomainEnumeration, "get_subdomains_from_subfinder", return_value={"ci.drakvuf.cert.pl"})
    def test_simple(self, mock_subfinder, mock_gau, mock_brute) -> None:  # type: ignore
        mock_subfinder.__name__ = "get_subdomains_from_subfinder"
        mock_gau.__name__ = "get_subdomains_from_gau"
        mock_brute.__name__ = "get_subdomains_by_dns_brute_force"
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "cert.pl"},
        )
        results = self.run_task(task)

        found = any(item.payload["domain"] == "ci.drakvuf.cert.pl" for item in results)
        self.assertTrue(found)
        mock_subfinder.assert_called_once_with("cert.pl")
