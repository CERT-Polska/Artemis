import os
import unittest
import unittest.mock

from artemis.reporting.base.language import Language
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.modules.cors_scanner.reporter import CORSScannerReporter


class CORSScannerReporterTest(unittest.TestCase):
    def _make_task_result(self, status="INTERESTING", findings=None):
        return {
            "created_at": None,
            "headers": {
                "receiver": "cors_scanner",
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
            },
        }

    def test_creates_report_for_interesting_result(self) -> None:
        findings = [
            {
                "issue": "arbitrary_origin_reflected",
                "origin_sent": "https://evil-attacker.com",
                "acao_header": "https://evil-attacker.com",
                "acac_header": "true",
                "request_method": "GET",
            }
        ]
        task_result = self._make_task_result(findings=findings)
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].report_type, ReportType("cors_misconfiguration"))
        self.assertEqual(reports[0].additional_data["findings"], findings)

    def test_no_report_for_ok_status(self) -> None:
        task_result = self._make_task_result(status="OK", findings=[])
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_no_report_for_wrong_receiver(self) -> None:
        task_result = self._make_task_result(findings=[{"issue": "test", "request_method": "GET"}])
        task_result["headers"]["receiver"] = "other_module"
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_no_report_for_empty_findings(self) -> None:
        task_result = self._make_task_result(status="INTERESTING", findings=[])
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_no_report_for_non_dict_result(self) -> None:
        task_result = self._make_task_result()
        task_result["result"] = "not a dict"
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 0)

    def test_report_type_constant(self) -> None:
        self.assertEqual(CORSScannerReporter.CORS_MISCONFIGURATION, ReportType("cors_misconfiguration"))

    def test_reports_from_task_result_integration(self) -> None:
        import sys
        from artemis.config import Config
        from artemis.reporting.base.reporters import get_all_reporters, reports_from_task_result

        nuclei_path = os.path.join(os.path.dirname(__file__), "..", "..", "artemis", "modules", "data", "nuclei_template_groups.json")
        nuclei_mod_key = "artemis.reporting.modules.nuclei.reporter"

        # Remove cached nuclei reporter module so it re-imports with patched config
        sys.modules.pop(nuclei_mod_key, None)
        get_all_reporters.cache_clear()

        original_val = Config.Modules.Nuclei.NUCLEI_TEMPLATE_GROUPS_FILE
        try:
            Config.Modules.Nuclei.NUCLEI_TEMPLATE_GROUPS_FILE = nuclei_path

            findings = [
                {
                    "issue": "null_origin_with_credentials",
                    "origin_sent": "null",
                    "acao_header": "null",
                    "acac_header": "true",
                    "request_method": "GET",
                }
            ]
            task_result = self._make_task_result(findings=findings)
            reports = reports_from_task_result(task_result, Language.en_US)
            cors_reports = [r for r in reports if r.report_type == ReportType("cors_misconfiguration")]
            self.assertEqual(len(cors_reports), 1)
        finally:
            Config.Modules.Nuclei.NUCLEI_TEMPLATE_GROUPS_FILE = original_val
            get_all_reporters.cache_clear()

    def test_multiple_findings_single_report(self) -> None:
        findings = [
            {
                "issue": "arbitrary_origin_reflected",
                "origin_sent": "https://evil.com",
                "acao_header": "https://evil.com",
                "acac_header": "true",
                "request_method": "GET",
            },
            {
                "issue": "null_origin_with_credentials",
                "origin_sent": "null",
                "acao_header": "null",
                "acac_header": "true",
                "request_method": "OPTIONS",
            },
        ]
        task_result = self._make_task_result(findings=findings)
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(len(reports[0].additional_data["findings"]), 2)

    def test_get_email_template_fragments(self) -> None:
        fragments = CORSScannerReporter.get_email_template_fragments()
        self.assertEqual(len(fragments), 1)

    def test_report_target_and_top_level_target(self) -> None:
        findings = [
            {
                "issue": "wildcard_with_credentials",
                "origin_sent": "https://evil.com",
                "acao_header": "*",
                "acac_header": "true",
                "request_method": "GET",
            }
        ]
        task_result = self._make_task_result(findings=findings)
        reports = CORSScannerReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].top_level_target, "example.com")
