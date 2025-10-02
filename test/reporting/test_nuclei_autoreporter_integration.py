from test.base import BaseReportingTest

from artemis.modules.nuclei import Nuclei
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.language import Language
from artemis.reporting.modules.nuclei.reporter import NucleiReporter
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporters import assets_from_task_result


class NucleiAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Nuclei  # type: ignore

    def test_reporting(self) -> None:
        data = self.obtain_http_task_result("nuclei", "test-phpmyadmin-easy-password")
        message = self.task_result_to_message(data)
        self.assertIn(
            "The following addresses contain login panels, analytics services, management panels etc.", message
        )
        self.assertIn("http://test-phpmyadmin-easy-password:80: phpMyAdmin panel was detected.", message)

    def test_asset_discovery(self) -> None:
        data = self.obtain_http_task_result("nuclei", "test-old-wordpress")
        message = self.task_result_to_message(data)
        # this should not be reported as WordPress panel detection template is skipped from reporting (but not from running)
        self.assertNotIn("test-old-wordpress", message)
        assets = assets_from_task_result(data)
        self.assertEqual(
            assets,
            [
                Asset(
                    asset_type=AssetType.EXPOSED_PANEL,
                    name="http://test-old-wordpress:80/wp-login.php",
                    additional_type="wordpress-login",
                    original_karton_name=None,
                    last_domain=None,
                )
            ],
        )

    def test_curl_command_minimization_short_url(self) -> None:
        """Test that short curl commands are not truncated."""
        short_cmd = "curl -X GET http://example.com/path?param1=value1"
        result = NucleiReporter._minimize_curl_command(short_cmd, max_length=200)
        self.assertEqual(result, short_cmd)

    def test_curl_command_minimization_long_url(self) -> None:
        """Test that long curl commands with many query parameters are truncated."""
        # Simulate the issue example with many fuzzing parameters
        base_url = "http://example.com/vulnerabilities/sqli.php"
        params = "&".join([f"param{i}=http%3A%2F%2F127.0.0.1%2Fabc.html" for i in range(50)])
        long_url = f"{base_url}?{params}"
        long_cmd = f"curl -X GET {long_url}"

        result = NucleiReporter._minimize_curl_command(long_cmd, max_length=200)

        # Result should be shorter than original
        self.assertLess(len(result), len(long_cmd))
        # Should still contain the base URL and domain
        self.assertIn("example.com", result)
        self.assertIn("/vulnerabilities/sqli.php", result)
        # Should indicate truncation
        self.assertIn("...", result)
        # Should be within max_length
        self.assertLessEqual(len(result), 200)

    def test_curl_command_minimization_none(self) -> None:
        """Test that None curl command is handled gracefully."""
        result = NucleiReporter._minimize_curl_command(None)
        self.assertIsNone(result)

    def test_curl_command_minimization_no_query_params(self) -> None:
        """Test that URLs without query parameters are not modified."""
        cmd = "curl -X POST http://example.com/api/endpoint"
        result = NucleiReporter._minimize_curl_command(cmd, max_length=200)
        self.assertEqual(result, cmd)

    def test_curl_command_in_reports_with_long_url(self) -> None:
        """Test that curl_command in reports is properly minimized."""
        # Create a mock task result with a long curl command
        long_params = "&".join([f"param{i}=value{i}" for i in range(100)])
        long_url = f"http://test-example.com/path?{long_params}"
        long_curl = f"curl -X GET {long_url}"

        task_result = {
            "created_at": None,
            "headers": {"receiver": "nuclei"},
            "result": [
                {
                    "template": "http/cves/test-cve.yaml",
                    "template-id": "test-cve-2024",
                    "info": {
                        "name": "Test Vulnerability",
                        "description": "Test vulnerability description",
                        "severity": "high",
                    },
                    "matched-at": long_url,
                    "curl-command": long_curl,
                }
            ],
            "payload": {"last_domain": "test-example.com"},
            "payload_persistent": {"original_domain": "test-example.com"},
        }

        reports = NucleiReporter.create_reports(task_result, Language.en_US)

        # Should have created one report
        self.assertEqual(len(reports), 1)

        # curl_command should be minimized
        curl_cmd = reports[0].additional_data["curl_command"]
        self.assertIsNotNone(curl_cmd)
        self.assertLess(len(curl_cmd), len(long_curl))
        self.assertIn("...", curl_cmd)
