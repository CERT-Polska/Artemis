from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.domain_scanner import DomainScanner


class DomainScannerTest(ArtemisModuleTestCase):
    karton_class = DomainScanner  # type: ignore

    def test_domain_existence(self) -> None:
        test_cases = [
            {"domain": "cert.pl", "exists": True},
            {"domain": "doesnotexist.in", "exists": False},
        ]

        for case in test_cases:
            task = Task(
                {"type": TaskType.DOMAIN.value},
                payload={"domain": case["domain"]},
            )
            results = self.run_task(task)

            if case["exists"]:
                self.assertIn(case["domain"], results[0].payload["existing_domains"])
            else:
                self.assertIn(case["domain"], results[0].payload["non_existing_domains"])
