import unittest
from typing import Any, List, Set
from unittest.mock import MagicMock, patch

from karton.core import Task
from karton.core.test import ConfigMock

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.scripts_unregistered_domains import ScriptsUnregisteredDomains

REGISTERED_DOMAINS = {"registered-example.pl"}


def _lookup(domain: str, query_type: str = "A") -> Set[str]:
    return {"192.0.2.1"} if domain in REGISTERED_DOMAINS else set()


class ScriptsUnregisteredDomainsTest(unittest.TestCase):
    module: ScriptsUnregisteredDomains

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = ScriptsUnregisteredDomains(config=ConfigMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def _scan(self, html: str) -> Any:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"url": "https://scanned-example.pl/"},
        )
        response = MagicMock()
        response.content = html
        with (
            patch.object(self.module, "http_get", return_value=response),
            patch("artemis.modules.scripts_unregistered_domains.lookup", side_effect=_lookup),
            patch("artemis.modules.scripts_unregistered_domains.perform_whois", return_value=None),
            patch.object(self.module, "save_task_result") as save_task_result,
        ):
            self.module.run(task)
        return save_task_result.call_args.kwargs

    def _found_domains(self, html: str) -> List[str]:
        return [item["domain"] for item in self._scan(html)["data"]]

    def test_script_from_unregistered_domain_is_reported(self) -> None:
        result = self._scan('<script src="https://cdn.unregistered-example.pl/a.js"></script>')
        self.assertEqual(result["status"], TaskStatus.INTERESTING)
        self.assertEqual([item["domain"] for item in result["data"]], ["cdn.unregistered-example.pl"])

    def test_script_from_unregistered_domain_with_port_is_reported(self) -> None:
        result = self._scan('<script src="https://cdn.unregistered-example.pl:8443/a.js"></script>')
        self.assertEqual(result["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            result["status_reason"],
            "https://scanned-example.pl/ loads script from unregistered domain cdn.unregistered-example.pl",
        )
        self.assertEqual(
            result["data"],
            [
                {
                    "src": "https://cdn.unregistered-example.pl:8443/a.js",
                    "domain": "cdn.unregistered-example.pl",
                    "privatesuffix": "unregistered-example.pl",
                }
            ],
        )

    def test_script_from_unregistered_domain_with_credentials_is_reported(self) -> None:
        html = '<script src="https://user@cdn.unregistered-example.pl/a.js"></script>'
        self.assertEqual(self._found_domains(html), ["cdn.unregistered-example.pl"])

    def test_uppercase_domain_is_reported_in_lowercase(self) -> None:
        html = '<script src="//CDN.Unregistered-Example.PL/a.js"></script>'
        self.assertEqual(self._found_domains(html), ["cdn.unregistered-example.pl"])

    def test_script_from_registered_domain_with_port_is_not_reported(self) -> None:
        result = self._scan('<script src="https://cdn.registered-example.pl:8443/a.js"></script>')
        self.assertEqual(result["status"], TaskStatus.OK)
        self.assertEqual(result["data"], [])

    def test_relative_script_is_not_checked(self) -> None:
        result = self._scan('<script src="/static/a.js"></script>')
        self.assertEqual(result["status"], TaskStatus.OK)
        self.assertEqual(result["data"], [])


if __name__ == "__main__":
    unittest.main()
