import unittest

import requests

from artemis import http_requests

# The nginx-with-sni-tls test service listens on 443, requires the correct SNI
# (it rejects the handshake otherwise) and serves a self-signed certificate. It is
# the only test target that lets us exercise the real TLS path through
# SSLContextAdapter, which the rest of the module suite (HTTP-only targets) does not.
TLS_URL = "https://test-nginx-with-sni-tls/"
EXPECTED_BODY = "TLS with correct SNI works\n"


class HTTPRequestsTLSTestCase(unittest.TestCase):
    def test_https_request_succeeds(self) -> None:
        # A real TLS handshake with the correct SNI must still succeed after the SSL
        # context started being shared across requests instead of rebuilt each time.
        response = http_requests.get(TLS_URL, requests_per_second=0)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, EXPECTED_BODY)

    def test_ssl_adapter_is_mounted_once_per_session(self) -> None:
        # The adapter must be mounted once per session (keyed by the scheme), not on
        # every request. Three requests on a shared session must all succeed, the
        # https:// adapter must be our SSLContextAdapter, and the adapter dict must not
        # accumulate per-URL entries the way the previous session.mount(url, ...) did.
        session = requests.Session()
        statuses = [
            http_requests.request("get", TLS_URL, session=session, requests_per_second=0).status_code for _ in range(3)
        ]
        self.assertEqual(statuses, [200, 200, 200])
        self.assertIsInstance(session.adapters.get("https://"), http_requests.SSLContextAdapter)
        self.assertEqual(set(session.adapters), {"http://", "https://"})

    def test_content_is_cached(self) -> None:
        # HTTPResponse.content is a cached_property: decoded once on first access and
        # reused afterwards (callers such as bruter's filter read it several times).
        response = http_requests.get(TLS_URL, requests_per_second=0)
        self.assertNotIn("content", response.__dict__)
        _ = response.content
        self.assertIn("content", response.__dict__)


if __name__ == "__main__":
    unittest.main()
