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
        result = self.karton.get_subdomains_from_subfinder("cert.pl")
        self.assertTrue("ci.drakvuf.cert.pl" in result)

    def test_get_subdomains_from_gau(self) -> None:
        result = self.karton.get_subdomains_from_gau("cert.pl")
        self.assertTrue("vortex.cert.pl" in result)

    def test_subfinder_all_is_superset_of_all_recursive(self) -> None:
        """
        Make sure our assumptions about subfinder are correct - that skipping the `-recursive` option
        just enables all modules (not only the recursive ones), but doesn't change the behavior of the
        recursive modules (i.e. doesn't make them non-recursive). We check this by checking that the
        set of subdomains returned by `subfinder -all` contains all subdomains returned by `subfinder -all -recursive`.
        """
        domains = ["cert.pl", "nask.pl", "example.com", "badssl.com"]

        for domain in domains:
            # Old behavior (with -recursive)
            recursive_result = (
                self.karton.get_subdomains_from_tool(
                    "subfinder",
                    ["-d", domain, "-silent", "-all", "-recursive"],
                    domain,
                )
                or set()
            )

            # New behavior (without -recursive)
            all_result = self.karton.get_subdomains_from_subfinder(domain) or set()

            missing = recursive_result - all_result

            self.assertEqual(
                missing,
                set(),
                f"For domain {domain} recursive result is not a subset of all result. " f"Missing entries: {missing}",
            )
