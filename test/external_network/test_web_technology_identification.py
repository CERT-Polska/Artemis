import logging
import time
import unittest

from artemis.web_technology_identification import run_tech_detection, to_tag_strings

NUM_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 10


class TestWebTechnologyIdentification(unittest.TestCase):
    def test_skipping_ssl_verification(self) -> None:
        targets = ["https://self-signed.badssl.com"]

        logger = logging.Logger("test_logger")
        # self-signed.badssl.com sometimes resets the connection, which also ends with an empty result. Retrying
        # doesn't hide a real regression: if SSL verification isn't skipped, every attempt fails the same way.
        for attempt in range(NUM_ATTEMPTS):
            tech_results = run_tech_detection(targets, logger=logger)
            if all(tech_results.get(target) for target in targets):
                break
            if attempt < NUM_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY_SECONDS)

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
