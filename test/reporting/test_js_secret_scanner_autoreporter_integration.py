import os
import unittest
import unittest.mock

from artemis.reporting.base.language import Language
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.modules.js_secret_scanner.reporter import JSSecretScannerReporter


class JSSecretScannerReporterTest(unittest.TestCase):
    def _make_task_result(self, status="INTERESTING", findings=None):
        return {
            "created_at": None,
            "headers": {
                "receiver": "js_secret_scanner",
                "type": "service",
                "service": "http",
            },
            "payload": {
                "host": "example.com",
                "port": 443,
                "last_domain": "example.com",
            },
            "payload_persistent": {
                "original_domain": "example.com",
            },
            "status": status,
            "result": {
                "findings": findings or [],
                "js_files_scanned": 5,
                "inline_scripts_scanned": True,
            },
        }

    def test_creates_report_for_interesting_result(self) -> None:
        findings = [
            {
                "pattern_name": "AWS Access Key ID",
                "severity": "high",
                "js_url": "https://example.com/app.js",
                "matched_text_redacted": "AKIAIOSF...",
                "match_start": 42,
            }
        ]
        task_result = self._make_task_result(findings=findings)
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].report_type, ReportType("exposed_secrets_in_js"))
        self.assertEqual(reports[0].additional_data["high_count"], 1)
        self.assertEqual(reports[0].additional_data["medium_count"], 0)
        self.assertIn("AWS Access Key ID", reports[0].additional_data["secret_types"])

    def test_no_report_for_ok_status(self) -> None:
        task_result = self._make_task_result(status="OK", findings=[])
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_no_report_for_wrong_receiver(self) -> None:
        findings = [{"pattern_name": "test", "severity": "high"}]
        task_result = self._make_task_result(findings=findings)
        task_result["headers"]["receiver"] = "other_module"
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_no_report_for_empty_findings(self) -> None:
        task_result = self._make_task_result(status="INTERESTING", findings=[])
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_no_report_for_non_dict_result(self) -> None:
        task_result = self._make_task_result()
        task_result["result"] = "not a dict"
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_report_type_constant(self) -> None:
        self.assertEqual(JSSecretScannerReporter.EXPOSED_SECRETS_IN_JS, ReportType("exposed_secrets_in_js"))

    def test_reports_from_task_result_integration(self) -> None:
        import sys
        from artemis.config import Config
        from artemis.reporting.base.reporters import get_all_reporters, reports_from_task_result

        nuclei_path = os.path.join(os.path.dirname(__file__), "..", "..", "artemis", "modules", "data", "nuclei_template_groups.json")
        nuclei_mod_key = "artemis.reporting.modules.nuclei.reporter"

        sys.modules.pop(nuclei_mod_key, None)
        get_all_reporters.cache_clear()

        original_val = Config.Modules.Nuclei.NUCLEI_TEMPLATE_GROUPS_FILE
        try:
            Config.Modules.Nuclei.NUCLEI_TEMPLATE_GROUPS_FILE = nuclei_path

            findings = [
                {
                    "pattern_name": "Stripe Secret Key",
                    "severity": "high",
                    "js_url": "https://example.com/checkout.js",
                    "matched_text_redacted": "sk_live_...",
                    "match_start": 100,
                }
            ]
            task_result = self._make_task_result(findings=findings)
            reports = reports_from_task_result(task_result, Language.en_US)
            js_reports = [r for r in reports if r.report_type == ReportType("exposed_secrets_in_js")]
            self.assertEqual(len(js_reports), 1)
        finally:
            Config.Modules.Nuclei.NUCLEI_TEMPLATE_GROUPS_FILE = original_val
            get_all_reporters.cache_clear()

    def test_mixed_severity_findings(self) -> None:
        findings = [
            {
                "pattern_name": "AWS Access Key ID",
                "severity": "high",
                "js_url": "https://example.com/app.js",
                "matched_text_redacted": "AKIAIO...",
                "match_start": 10,
            },
            {
                "pattern_name": "JSON Web Token",
                "severity": "medium",
                "js_url": "https://example.com/config.js",
                "matched_text_redacted": "eyJhbG...",
                "match_start": 20,
            },
            {
                "pattern_name": "Hardcoded Password",
                "severity": "medium",
                "js_url": "https://example.com/app.js",
                "matched_text_redacted": "passwo...",
                "match_start": 30,
            },
        ]
        task_result = self._make_task_result(findings=findings)
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].additional_data["high_count"], 1)
        self.assertEqual(reports[0].additional_data["medium_count"], 2)
        self.assertEqual(
            reports[0].additional_data["secret_types"],
            ["AWS Access Key ID", "Hardcoded Password", "JSON Web Token"],
        )

    def test_get_email_template_fragments(self) -> None:
        fragments = JSSecretScannerReporter.get_email_template_fragments()
        self.assertEqual(len(fragments), 1)

    def test_report_target_and_top_level_target(self) -> None:
        findings = [
            {
                "pattern_name": "Private Key",
                "severity": "high",
                "js_url": "https://example.com/app.js (inline-0)",
                "matched_text_redacted": "-----BE...",
                "match_start": 0,
            }
        ]
        task_result = self._make_task_result(findings=findings)
        reports = JSSecretScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].top_level_target, "example.com")
