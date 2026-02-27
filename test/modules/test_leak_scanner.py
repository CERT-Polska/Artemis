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
        self.assertGreater(data["pdfs_checked"], 0)
        self.assertEqual(len(data["pdfs_with_leaked_data"]), 1)

        pdf_result = data["pdfs_with_leaked_data"][0]
        self.assertIn("bad_redaction.pdf", pdf_result["url"])
        self.assertGreater(len(pdf_result["leaked_items"]), 0)

        # Verify that x-ray actually found the hidden text
        leaked_texts = [item["text"] for item in pdf_result["leaked_items"]]
        found_secret = any("SECRET" in text or "John Doe" in text for text in leaked_texts)
        self.assertTrue(found_secret, f"Expected to find hidden text but got: {leaked_texts}")
