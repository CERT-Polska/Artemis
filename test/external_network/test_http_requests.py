import unittest

from artemis.http_requests import get
from artemis.ssrf import SSRFDetected


class SSRFFenceTestCase(unittest.TestCase):
    def test_ssrf_fence(self) -> None:
        self.assertIn("<title>CERT Polska</title>", get("https://cert.pl").text)
        self.assertIn("free app that makes your Internet faster", get("https://1.1.1.1").text)
        with self.assertRaises(SSRFDetected):
            get("http://127.0.0.1")
        with self.assertRaises(SSRFDetected):
            get("https://127.0.0.1")
        with self.assertRaises(SSRFDetected):
            get("http://redis")
        with self.assertRaises(SSRFDetected):
            get("http://postgres")
        with self.assertRaises(SSRFDetected):
            get("http://localhost")
        with self.assertRaises(SSRFDetected):
            get("http://domaincontrol.com")
