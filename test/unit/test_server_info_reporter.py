#!/usr/bin/env python3
import os
import unittest

os.environ.setdefault("POSTGRES_CONN_STR", "postgresql://postgres:postgres@localhost/artemis")
os.environ.setdefault("DB_CONN_STR", os.environ["POSTGRES_CONN_STR"])
os.environ.setdefault("REDIS_CONN_STR", "redis://localhost")

from artemis.reporting.base.language import Language
from artemis.reporting.modules.server_info.reporter import ServerInfoReporter


def _make_task_result(receiver: str, status: str, result: dict) -> dict:
    return {
        "headers": {"receiver": receiver, "type": "service", "service": "http"},
        "payload": {"host": "example.com", "port": 443},
        "payload_persistent": {"original_domain": "example.com"},
        "status": status,
        "result": result,
        "created_at": "2025-01-01T00:00:00",
        "target_string": "example.com:443",
    }


class TestServerInfoReporter(unittest.TestCase):
    def test_creates_report_for_interesting_result(self) -> None:
        task_result = _make_task_result(
            receiver="server_info",
            status="INTERESTING",
            result={
                "detected": [
                    {"name": "Apache", "version": "2.4.53", "category": "web_server", "header": "Server", "raw": "Apache/2.4.53"},
                ],
                "raw_headers": {"Server": "Apache/2.4.53"},
                "url": "https://example.com:443",
            },
        )
        reports = ServerInfoReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(str(reports[0].report_type), "server_info_disclosure")
        self.assertEqual(len(reports[0].additional_data["detected"]), 1)
        self.assertEqual(reports[0].additional_data["detected"][0]["name"], "Apache")

    def test_no_report_for_ok_status(self) -> None:
        task_result = _make_task_result(
            receiver="server_info",
            status="OK",
            result={"detected": [], "raw_headers": {}, "url": "https://example.com:443"},
        )
        reports = ServerInfoReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(reports, [])

    def test_no_report_for_wrong_receiver(self) -> None:
        task_result = _make_task_result(
            receiver="humble",
            status="INTERESTING",
            result={
                "detected": [{"name": "nginx", "category": "web_server", "header": "Server", "raw": "nginx"}],
            },
        )
        reports = ServerInfoReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(reports, [])

    def test_no_report_for_empty_detected(self) -> None:
        task_result = _make_task_result(
            receiver="server_info",
            status="INTERESTING",
            result={"detected": [], "raw_headers": {}, "url": "https://example.com:443"},
        )
        reports = ServerInfoReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(reports, [])

    def test_no_report_for_non_dict_result(self) -> None:
        task_result = _make_task_result(
            receiver="server_info",
            status="INTERESTING",
            result="error string",
        )
        task_result["result"] = "error string"
        reports = ServerInfoReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(reports, [])

    def test_multiple_detected_items(self) -> None:
        task_result = _make_task_result(
            receiver="server_info",
            status="INTERESTING",
            result={
                "detected": [
                    {"name": "nginx", "version": "1.18.0", "category": "web_server", "header": "Server", "raw": "nginx/1.18.0"},
                    {"name": "PHP", "version": "8.1.2", "category": "programming_language", "header": "X-Powered-By", "raw": "PHP/8.1.2"},
                ],
                "raw_headers": {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"},
                "url": "https://example.com:443",
            },
        )
        reports = ServerInfoReporter.create_reports(task_result, Language.en_US)
        self.assertEqual(len(reports), 1)
        self.assertEqual(len(reports[0].additional_data["detected"]), 2)

    def test_report_type_class_attribute(self) -> None:
        self.assertEqual(str(ServerInfoReporter.SERVER_INFO_DISCLOSURE), "server_info_disclosure")

    def test_email_template_fragments_exist(self) -> None:
        fragments = ServerInfoReporter.get_email_template_fragments()
        self.assertEqual(len(fragments), 1)

    def test_normal_form_rules(self) -> None:
        rules = ServerInfoReporter.get_normal_form_rules()
        self.assertIn(ServerInfoReporter.SERVER_INFO_DISCLOSURE, rules)


if __name__ == "__main__":
    unittest.main()
