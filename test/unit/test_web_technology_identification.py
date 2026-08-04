import json
import logging
import subprocess
import unittest
from typing import List
from unittest.mock import MagicMock, patch

from artemis.web_technology_identification import (
    TechDetectionFailedException,
    run_tech_detection,
    to_tag_strings,
)


class TestWebTechnologyIdentification(unittest.TestCase):
    def test_run_tech_detection(self) -> None:
        targets = [
            "http://test-old-wordpress",
            "http://test-old-joomla",
        ]

        logger = logging.Logger("test_logger")
        tech_results = run_tech_detection(targets, logger=logger)

        expected_results = {
            "http://test-old-wordpress": [
                "Apache HTTP Server:2.4.53",
                "WordPress Block Editor",
                "WordPress Site Editor",
                "WordPress:5.9.3",
                "MySQL",
                "PHP:7.4.29",
                "Debian",
            ],
            "http://test-old-joomla": [
                "Joomla",
                "Debian",
                "Apache HTTP Server:2.4.51",
                "PHP:8.0.15",
            ],
        }

        for target in targets:
            self.assertIn(target, tech_results)
            detected_tags = set(to_tag_strings(tech_results[target]))
            self.assertEqual(detected_tags, set(expected_results[target]))

            # to_tag_strings drops the CPE, so check it separately - it is what a CVE lookup
            # keys on. Apache is detected on both targets, and its version slot stays a
            # wildcard because Wappalyzer reports the version apart from the CPE template.
            (apache,) = [tech for tech in tech_results[target] if tech.name == "Apache HTTP Server"]
            self.assertEqual(apache.cpe, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")

    def test_skipping_ssl_verification(self) -> None:
        targets = ["https://self-signed.badssl.com"]

        logger = logging.Logger("test_logger")
        tech_results = run_tech_detection(targets, logger=logger)

        # Without skipping SSL verification, the output is empty and the below error is logged:
        # Error fetching https://self-signed.badssl.com/: Get "https://self-signed.badssl.com/": tls: failed to verify certificate: x509: certificate signed by unknown authority
        expected_results = {
            "https://self-signed.badssl.com": [
                "Ubuntu",
                "Nginx:1.10.3",
            ],
        }

        for target in targets:
            self.assertIn(target, tech_results)
            detected_tags = set(to_tag_strings(tech_results[target]))
            self.assertEqual(detected_tags, set(expected_results[target]))

    @patch("artemis.web_technology_identification.subprocess.check_output")
    @patch("artemis.web_technology_identification.subprocess.run")
    @patch("artemis.web_technology_identification.os.path.exists", return_value=True)
    def test_dependencies_are_not_upgraded_at_runtime(
        self, _exists: MagicMock, mock_run: MagicMock, mock_check_output: MagicMock
    ) -> None:
        # The wappalyzergo version has to come from go.mod, not from whatever is newest upstream.
        # A `go get -u` here would mean production, CI and the pin all run different code, so a broken
        # upstream release would hit production and CI at the same moment, with no PR to revert.
        mock_check_output.return_value = b"{}"

        run_tech_detection(["http://example.com"], logger=logging.Logger("test_logger"))

        self.assertEqual(mock_run.call_args_list, [])

        # Checking that alone wouldn't be enough: `go get` smuggled through check_output (whose return
        # value is mocked here anyway) would leave this test green while restoring the old behaviour.
        # Assert on what is being executed instead of on which function executes it.
        commands: List[List[str]] = []
        for call in mock_run.call_args_list + mock_check_output.call_args_list:
            command = call.args[0] if call.args else call.kwargs.get("args")
            if command is None:
                self.fail(f"subprocess called without a command: {call}")
            commands.append(command)

        # Guards against the loop below becoming vacuous if the subprocess call ever goes away.
        self.assertIn(["go", "run"], [command[:2] for command in commands])

        for command in commands:
            self.assertNotIn("get", command, f"the wappalyzergo version must not be upgraded at runtime: {command}")

    @patch("artemis.web_technology_identification.subprocess.check_output")
    @patch("artemis.web_technology_identification.os.path.exists", return_value=True)
    def test_broken_detection_raises_instead_of_reporting_no_technologies(
        self, _exists: MagicMock, mock_check_output: MagicMock
    ) -> None:
        # Both ways the detection itself can break: the wrapper failing to run (no Go toolchain, no module,
        # unreachable module proxy) and it returning something that isn't the expected output. Neither may
        # be reported as "this target runs no technologies" - the callers have no way to tell the difference.
        mock_check_output.side_effect = subprocess.CalledProcessError(1, ["go", "run"])
        with self.assertRaises(TechDetectionFailedException):
            run_tech_detection(["http://example.com"], logger=logging.Logger("test_logger"))

        mock_check_output.side_effect = None
        mock_check_output.return_value = b"not json"
        with self.assertRaises(TechDetectionFailedException):
            run_tech_detection(["http://example.com"], logger=logging.Logger("test_logger"))

    @patch("artemis.web_technology_identification.os.path.exists", return_value=False)
    def test_missing_wrapper_raises_the_same_exception(self, _exists: MagicMock) -> None:
        # A missing main.go is the same class of failure, so a caller catching the domain exception
        # must not have to also know about FileNotFoundError.
        with self.assertRaises(TechDetectionFailedException):
            run_tech_detection(["http://example.com"], logger=logging.Logger("test_logger"))

    @patch("artemis.web_technology_identification.subprocess.check_output")
    @patch("artemis.web_technology_identification.os.path.exists", return_value=True)
    def test_url_absent_from_output_is_still_present(self, _exists: MagicMock, mock_check_output: MagicMock) -> None:
        # Wappalyzer returns only one of the two requested URLs; the omitted one must
        # still be present in the result (with an empty list) per the url -> list contract.
        mock_check_output.return_value = json.dumps(
            {
                "http://has-tech": [
                    {
                        "name": "Apache HTTP Server:2.4.53",
                        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        "categories": ["Web servers"],
                    }
                ],
            }
        ).encode("utf-8")

        logger = logging.Logger("test_logger")
        results = run_tech_detection(["http://has-tech", "http://no-tech"], logger=logger)

        self.assertIn("http://no-tech", results)
        self.assertEqual(results["http://no-tech"], [])
        self.assertEqual([tech.name for tech in results["http://has-tech"]], ["Apache HTTP Server"])
