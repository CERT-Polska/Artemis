from test.base import BaseReportingTest
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import TaskType, WebApplication
from artemis.modules.cve_lookup import CveLookup
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


def _make_nvd_response() -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "remote code execution in apache"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    return response


class CveLookupAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = CveLookup  # type: ignore

    def setUp(self) -> None:
        super().setUp()
        self.karton.cache.flush()
        # WEBAPP tasks trigger the framework's base-URL reachability check before run();
        # bypass it so the NVD mock only sees the module's own request.
        connection_check_patcher = patch(
            "artemis.module_base.ArtemisBase.check_connection_to_base_url_and_save_error",
            return_value=True,
        )
        connection_check_patcher.start()
        self.addCleanup(connection_check_patcher.stop)

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_cve_finding_renders_in_report(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_nvd_response()
        message = self._render_message_for_task()

        self.assertIn("Known CVEs were found", message)
        self.assertIn("CVE-2024-9999", message)
        self.assertIn("9.8", message)
        self.assertIn("Apache HTTP Server", message)

    def _render_message_for_task(self) -> str:
        url = "http://example.test:80"
        task = Task(
            {
                "type": TaskType.WEBAPP,
                "webapp": WebApplication.UNKNOWN.value,
            },
            payload={
                "url": url,
                "technologies": [
                    {
                        "name": "Apache HTTP Server",
                        "version": "2.4.53",
                        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        "categories": ["Web servers"],
                    },
                ],
            },
            payload_persistent={"original_domain": "example.test"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        task_result: Dict[str, Any] = {
            "created_at": None,
            "target_string": url,
            "headers": {"receiver": "cve_lookup"},
            "payload": {"url": url, "last_domain": "example.test"},
            "payload_persistent": {"original_domain": "example.test"},
            "status": "INTERESTING",
            "result": call.kwargs["data"],
        }

        reports = reports_from_task_result(task_result, Language.en_US)  # type: ignore
        message_template = self.generate_message_template()
        return message_template.render(
            {
                "data": {
                    "custom_template_arguments": {},
                    "contains_type": set([report.report_type for report in reports]),
                    "reports": reports,
                }
            }
        )
