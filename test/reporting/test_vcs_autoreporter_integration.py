from test.base import BaseReportingTest

from artemis.modules.vcs import VCSScanner
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result


class VCSAutoreporterIntegrationTest(BaseReportingTest):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = VCSScanner  # type: ignore

    def test_vcs_autoreporter(self) -> None:
        data = self.obtain_http_task_result("vcs", "test-service-with-exposed-vcs")
        reports = reports_from_task_result(data, Language.en_US)  # type: ignore

        # The remote URLs in the served .git/config and .svn/wc.db point at this very service
        # (a static nginx, which is not a git/svn server), so the clone attempts fail and both
        # folders get reported as non-public repositories.
        self.assertEqual(
            sorted(report.target for report in reports),
            [
                "http://test-service-with-exposed-vcs:80/.git/config",
                "http://test-service-with-exposed-vcs:80/.svn/wc.db",
            ],
        )
        self.assertEqual(set(report.report_type for report in reports), {"exposed_version_control_folder"})

        message = self.task_result_to_message(data)
        self.assertIn("http://test-service-with-exposed-vcs:80/.git/config", message)
        self.assertIn("http://test-service-with-exposed-vcs:80/.svn/wc.db", message)
