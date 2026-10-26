import subprocess
import unittest
from unittest.mock import MagicMock, patch

from artemis.config import Config
from artemis.modules.nuclei import (
    NUCLEI_TEMPLATES_LOCATION,
    _is_dast_finding,
    _reproduces_with_nuclei,
    build_common_nuclei_command,
)
from artemis.reporting.modules.nuclei.poc_url_utils import RefuzzError

HIT = b'{"template-id": "sqli-error-based", "fuzzing_parameter": "sortby"}\n'


class TestReproducesWithNuclei(unittest.TestCase):
    URL = "http://example.com/?search=%27%22%3E%3Cx%3E&sortby=%27"

    @patch("artemis.modules.nuclei.subprocess.check_output", return_value=HIT)
    def test_command_and_timeout(self, check_output: MagicMock) -> None:
        self.assertTrue(_reproduces_with_nuclei(self.URL, "template.yaml"))
        (call,) = check_output.call_args_list
        command = list(call.args[0])
        common = build_common_nuclei_command()
        self.assertEqual(command[: len(common)], common)
        self.assertEqual(command[command.index("-fuzzing-mode") + 1], "multiple")
        self.assertIn("-dast", command)
        self.assertEqual(call.kwargs["timeout"], Config.Modules.Nuclei.NUCLEI_REFUZZ_TIMEOUT_SECONDS)
        # The URL is sent with its matched-at payloads byte-for-byte.
        self.assertEqual(command[command.index("-u") + 1], self.URL)

    @patch("artemis.modules.nuclei.subprocess.check_output", return_value=b"")
    def test_no_hit(self, _check_output: MagicMock) -> None:
        self.assertFalse(_reproduces_with_nuclei(self.URL, "template.yaml"))

    @patch(
        "artemis.modules.nuclei.subprocess.check_output",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1),
    )
    def test_timeout_is_an_error_not_a_miss(self, _check_output: MagicMock) -> None:
        with self.assertRaisesRegex(RefuzzError, "timeout"):
            _reproduces_with_nuclei(self.URL, "template.yaml")

    @patch(
        "artemis.modules.nuclei.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(returncode=2, cmd="nuclei"),
    )
    def test_nuclei_failure_is_an_error_not_a_miss(self, _check_output: MagicMock) -> None:
        with self.assertRaisesRegex(RefuzzError, "exit_code_2"):
            _reproduces_with_nuclei(self.URL, "template.yaml")

    @patch("artemis.modules.nuclei.subprocess.check_output", side_effect=FileNotFoundError())
    def test_missing_binary_is_an_error_not_a_miss(self, _check_output: MagicMock) -> None:
        with self.assertRaisesRegex(RefuzzError, "nuclei_missing"):
            _reproduces_with_nuclei(self.URL, "template.yaml")


class TestIsDastFinding(unittest.TestCase):
    PRODUCTION_PATH = "/root/nuclei-templates/dast/vulnerabilities/sqli/sqli-error-based.yaml"

    def test_production_template_path(self) -> None:
        """The path Nuclei reports in production must enable minimization -
        otherwise it would silently never run."""
        self.assertTrue(_is_dast_finding({"template-path": self.PRODUCTION_PATH}))

    def test_path_built_the_way_the_scan_builds_it(self) -> None:
        # The scan passes NUCLEI_TEMPLATES_LOCATION + "dast/...", with whatever
        # slashes NUCLEI_TEMPLATES_LOCATION has.
        template = "dast/vulnerabilities/xss/reflected-xss.yaml"
        self.assertTrue(_is_dast_finding({"template-path": NUCLEI_TEMPLATES_LOCATION + template}))
        self.assertTrue(_is_dast_finding({"template-path": NUCLEI_TEMPLATES_LOCATION.rstrip("/") + "//" + template}))

    def test_relative_template_field(self) -> None:
        self.assertTrue(_is_dast_finding({"template": "dast/vulnerabilities/sqli/sqli-error-based.yaml"}))

    def test_non_dast_templates(self) -> None:
        for template in (
            "http/vulnerabilities/generic/xss-fuzz.yaml",
            "http/cves/2020/CVE-2020-28976.yaml",
            "http/vulnerabilities/dast/not-really.yaml",
        ):
            self.assertFalse(
                _is_dast_finding({"template": template, "template-path": NUCLEI_TEMPLATES_LOCATION + template})
            )
        self.assertFalse(_is_dast_finding({"template-id": "something"}))


if __name__ == "__main__":
    unittest.main()
