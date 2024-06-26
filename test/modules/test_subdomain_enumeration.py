from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.subdomain_enumeration import SubdomainEnumeration


class TestData(NamedTuple):
    domain: str
    expected_subdomain: str


class SubdomainEnumerationScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = SubdomainEnumeration  # type: ignore

    def test_simple(self) -> None:
        data = [TestData("cert.pl", "ci.drakvuf.cert.pl")]

        for entry in data:
            task = Task(
                {"type": TaskType.DOMAIN},
                payload={TaskType.DOMAIN: entry.domain},
            )
            results = self.run_task(task)

            found = False
            for item in results:
                if item.payload["domain"] == entry.expected_subdomain:
                    found = True
            self.assertTrue(found)

    def test_get_subdomains_from_subfinder(self) -> None:
        subdomain_enum = SubdomainEnumeration()
        result = subdomain_enum.get_subdomains_from_subfinder("cert.pl")
        self.assertEqual("ci.drakvuf.cert.pl", result)

    def test_get_subdomains_from_amass(self) -> None:
        subdomain_enum = SubdomainEnumeration()
        result = subdomain_enum.get_subdomains_from_amass("cert.pl")
        self.assertEqual("ci.drakvuf.cert.pl", result)
