import json
import logging
import unittest
from unittest.mock import MagicMock, patch

from artemis.web_technology_identification import run_tech_detection, to_tag_strings


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

    @patch("artemis.web_technology_identification.subprocess.check_output")
    @patch("artemis.web_technology_identification.subprocess.run")
    @patch("artemis.web_technology_identification.os.path.exists", return_value=True)
    def test_url_absent_from_output_is_still_present(
        self, _exists: MagicMock, _run: MagicMock, mock_check_output: MagicMock
    ) -> None:
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
