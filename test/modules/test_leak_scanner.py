from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.leak_scanner import LeakScanner


class LeakScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = LeakScanner  # type: ignore

    def test_bad_redaction_detected(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={
                "host": "test-leak-scanner-service",
                "port": 80,
                "ssl": False,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("leaked sensitive data", call.kwargs["status_reason"].lower())

        data = call.kwargs["data"]
        self.assertEqual(data["documents_checked"], 2)
        self.assertEqual(len(data["documents_with_findings"]), 1)

        doc_result = data["documents_with_findings"][0]
        self.assertIn("bad_redaction.pdf", doc_result["url"])

        self.assertIn("bad_redaction", doc_result["findings"])
        leaked_items = doc_result["findings"]["bad_redaction"]
        self.assertEqual(len(leaked_items), 1)
        self.assertEqual(leaked_items[0]["text"], "SECRET: John Doe SSN 123-45-6789")
