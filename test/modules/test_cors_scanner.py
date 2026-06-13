from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.cors_scanner import CorsScanner


class CorsScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = CorsScanner  # type: ignore

    def test_vulnerable_cors(self) -> None:
        """Server that reflects Origin + ACAC:true should be flagged."""
        self.mock_db.reset_mock()
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={
                "host": "test-cors-vulnerable",
                "port": 80,
                "ssl": False,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "CORS misconfiguration: server reflects arbitrary origins with credentials enabled",
        )
        findings = call.kwargs["data"]["findings"]
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["reflected_origin"], "https://evil.com")

    def test_safe_cors(self) -> None:
        """Server with no CORS or ACAO:* without credentials should not be flagged."""
        self.mock_db.reset_mock()
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={
                "host": "test-cors-safe",
                "port": 80,
                "ssl": False,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])
