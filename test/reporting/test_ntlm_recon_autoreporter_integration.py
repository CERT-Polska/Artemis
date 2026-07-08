from test.base import BaseReportingTest
from typing import Any, Dict

from artemis.binds import Service, TaskType
from artemis.modules.ntlm_recon import NTLMRecon
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class NTLMReconAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = NTLMRecon  # type: ignore

    @staticmethod
    def _task_result(host: str = "test-ntlm-host", port: int = 80) -> Dict[str, Any]:
        url = f"http://{host}:{port}/EWS/"
        return {
            "created_at": None,
            "target_string": f"http://{host}:{port}/",
            "headers": {
                "receiver": "ntlm_recon",
                "service": Service.HTTP,
                "type": TaskType.SERVICE,
            },
            "payload": {"last_domain": host, "host": host},
            "payload_persistent": {"original_domain": host},
            "status": "INTERESTING",
            "result": {
                "ntlm_endpoints": [
                    {
                        "url": url,
                        "decoded": True,
                        "data": {
                            "AD domain name": "CORP",
                            "Server name": "DC01",
                            "DNS domain name": "corp.example.com",
                            "FQDN": "DC01.corp.example.com",
                            "Parent DNS domain": "example.com",
                        },
                    }
                ]
            },
        }

    def test_reports_as_asset(self) -> None:
        assets = assets_from_task_result(self._task_result())
        self.assertEqual(
            {(asset.asset_type, asset.name, asset.additional_type) for asset in assets},
            {(AssetType.TECHNOLOGY, "http://test-ntlm-host:80/EWS/", "ntlm")},
        )

    def test_reports_as_low_severity_vulnerability(self) -> None:
        message = self.task_result_to_message(self._task_result())
        self.assertIn("expose NTLM authentication over HTTP", message)
        self.assertIn("http://test-ntlm-host:80/EWS/", message)
        self.assertIn("DC01.corp.example.com", message)

    def test_no_findings_produces_nothing(self) -> None:
        data = self._task_result()
        data["status"] = "OK"
        data["result"] = {"ntlm_endpoints": []}
        self.assertEqual(assets_from_task_result(data), [])
        self.assertNotIn("expose NTLM authentication over HTTP", self.task_result_to_message(data))
