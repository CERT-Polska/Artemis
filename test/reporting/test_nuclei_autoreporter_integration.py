from test.base import BaseReportingTest
from unittest.mock import patch

from artemis.modules.nuclei import Nuclei
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import (
    assets_from_task_result,
    reports_from_task_result,
)


class NucleiAutoreporterIntegrationTest(BaseReportingTest):
    karton_class = Nuclei  # type: ignore

    def setUp(self) -> None:
        # list of templates used in tests
        patcher = patch(
            "artemis.config.Config.Modules.Nuclei.DEBUG_STANDARD_NUCLEI_TEMPLATES_TO_RUN",
            [
                "http/exposed-panels/phpmyadmin-panel.yaml",
                "http/exposed-panels/wordpress-login.yaml",
                "dast/vulnerabilities/lfi/lfi-keyed.yaml",
                "dast/vulnerabilities/lfi/linux-lfi-fuzz.yaml",
                "dast/vulnerabilities/lfi/windows-lfi-fuzz.yaml",
            ],
        )
        patcher.start()

        return super().setUp()

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

    def test_report_one_lfi_template(self) -> None:
        data = self.obtain_http_task_result("nuclei", "test-dast-vuln-app", 5000)
        reports = reports_from_task_result(data, Language.en_US)  # type: ignore
        count = 0
        for report in reports:
            if "lfi" in report.additional_data["template_name"]:
                count += 1
        self.assertEqual(count, 1)
