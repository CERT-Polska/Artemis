from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task
from retry import retry

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

    @retry(tries=3, delay=10)
    def test_get_subdomains_from_gau(self) -> None:
        result = self.karton.get_subdomains_from_gau("cert.pl")
        self.assertTrue("vortex.cert.pl" in result)
<<<<<<< HEAD
<<<<<<< HEAD

    def test_recursive_enumeration(self) -> None:
        """The module used to mark discovered subdomains as "done" immediately,
        causing any task for that subdomain to be skipped later.  That prevented
        recursive enumeration and broke the chain.

        After the fix we should be able to run enumeration on a subdomain and get
        its own children.
        """

        # stub out the three discovery functions with predictable behaviour
        def fake_subfinder(domain: str) -> Optional[Set[str]]:
            if domain == "example.com":
                return {"foo.example.com"}
            if domain == "foo.example.com":
                return {"bar.foo.example.com"}
            return set()

        self.karton.get_subdomains_from_subfinder = fake_subfinder
        self.karton.get_subdomains_from_gau = lambda d: set()
        self.karton.get_subdomains_by_dns_brute_force = lambda d: set()

        # run enumeration on the top‑level domain
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "example.com"},
        )
        results = self.run_task(task)
        self.assertTrue(any(r.payload["domain"] == "foo.example.com" for r in results))

        # run enumeration on the subdomain generated above; this should not be
        # skipped and we expect to see the next level
        subtask = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN: "foo.example.com"},
        )
        self.karton.redis.flushall()  # clear the cache to isolate the test
        subresults = self.run_task(subtask)
        self.assertTrue(any(r.payload["domain"] == "bar.foo.example.com" for r in subresults))
=======
>>>>>>> parent of 68fd802 (fix broken subdomain enum chain)
=======
>>>>>>> parent of 68fd802 (fix broken subdomain enum chain)
