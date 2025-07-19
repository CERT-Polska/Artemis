import logging
import unittest

from artemis.web_technology_identification import run_tech_detection


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
            self.assertEqual(set(tech_results[target]), set(expected_results[target]))

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
            self.assertEqual(set(tech_results[target]), set(expected_results[target]))
