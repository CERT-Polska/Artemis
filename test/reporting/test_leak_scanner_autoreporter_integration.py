from test.base import BaseReportingTest

from artemis.modules.leak_scanner import LeakScanner


class LeakScannerAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = LeakScanner  # type: ignore

    def test_leak_scanner_report(self) -> None:
        data = self.obtain_http_task_result("leak_scanner", "test-leak-scanner-service")
        message = self.task_result_to_message(data)
        self.assertIn(
            "The following PDF documents contain improperly redacted (censored) sensitive data that can be extracted:",
            message,
        )
        self.assertIn("bad_redaction.pdf", message)
