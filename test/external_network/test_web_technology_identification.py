import logging
import unittest

from artemis.web_technology_identification import run_tech_detection, to_tag_strings


class TestWebTechnologyIdentification(unittest.TestCase):
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
