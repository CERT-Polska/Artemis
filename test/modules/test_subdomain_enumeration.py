from test.base import ArtemisModuleTestCase
from typing import NamedTuple
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.subdomain_enumeration import SubdomainEnumeration, WildcardDNSInfo


class TestData(NamedTuple):
    domain: str
    expected_subdomain: str


class SubdomainEnumerationScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = SubdomainEnumeration  # type: ignore

    def test_simple(self) -> None:
        data = [TestData("cert.pl", "ci.drakvuf.cert.pl")]

        for entry in data:
            task = Task(
                {"type": TaskType.DOMAIN},
                payload={TaskType.DOMAIN: entry.domain},
            )
            results = self.run_task(task)

            found = False
            for item in results:
                if item.payload["domain"] == entry.expected_subdomain:
                    found = True
            self.assertTrue(found)

    def test_get_subdomains_from_subfinder(self) -> None:
        result = self.karton.get_subdomains_from_subfinder("cert.pl")
        self.assertTrue("ci.drakvuf.cert.pl" in result)

    def test_get_subdomains_from_gau(self) -> None:
        result = self.karton.get_subdomains_from_gau("cert.pl")
        self.assertTrue("vortex.cert.pl" in result)


class WildcardDNSDetectionTest(ArtemisModuleTestCase):
    """Unit tests for the wildcard DNS detection feature."""

    karton_class = SubdomainEnumeration  # type: ignore

    # --- _detect_wildcard_dns tests ---

    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_detect_wildcard_dns_all_probes_resolve(self, mock_lookup: MagicMock) -> None:
        """All random probes resolve → wildcard detected."""
        mock_lookup.return_value = {"1.2.3.4"}
        info = self.karton._detect_wildcard_dns("example.com")
        self.assertTrue(info.is_wildcard)
        self.assertIn("1.2.3.4", info.wildcard_ips)

    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_detect_no_wildcard_dns(self, mock_lookup: MagicMock) -> None:
        """No probes resolve → no wildcard."""
        from artemis.resolvers import ResolutionException

        mock_lookup.side_effect = ResolutionException("NXDOMAIN")
        info = self.karton._detect_wildcard_dns("example.com")
        self.assertFalse(info.is_wildcard)
        self.assertEqual(info.wildcard_ips, set())

    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_detect_wildcard_partial_probes(self, mock_lookup: MagicMock) -> None:
        """Some probes resolve but below threshold → no wildcard."""
        from artemis.resolvers import ResolutionException

        call_count = 0

        def side_effect(domain: str, *args, **kwargs):  # type: ignore
            nonlocal call_count
            call_count += 1
            # Only 3 out of 10 probes resolve (below 0.8 threshold)
            if call_count <= 3:
                return {"1.2.3.4"}
            raise ResolutionException("NXDOMAIN")

        mock_lookup.side_effect = side_effect
        info = self.karton._detect_wildcard_dns("example.com")
        self.assertFalse(info.is_wildcard)

    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_detect_wildcard_multi_ip(self, mock_lookup: MagicMock) -> None:
        """Wildcard DNS returning multiple IPs across probes → all collected."""
        call_count = 0

        def side_effect(domain: str, *args, **kwargs):  # type: ignore
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 0:
                return {"1.2.3.4"}
            return {"5.6.7.8"}

        mock_lookup.side_effect = side_effect
        info = self.karton._detect_wildcard_dns("example.com")
        self.assertTrue(info.is_wildcard)
        self.assertEqual(info.wildcard_ips, {"1.2.3.4", "5.6.7.8"})

    # --- _is_wildcard_response tests ---

    @patch("artemis.modules.subdomain_enumeration.http_requests")
    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_wildcard_response_dns_unique(self, mock_lookup: MagicMock, mock_http: MagicMock) -> None:
        """Subdomain resolves to IPs outside wildcard set → NOT wildcard."""
        mock_lookup.return_value = {"9.9.9.9"}
        info = WildcardDNSInfo(is_wildcard=True, wildcard_ips={"1.2.3.4"})
        self.assertFalse(self.karton._is_wildcard_response("unique.example.com", info))
        # HTTP should not be called since DNS already showed uniqueness.
        mock_http.get.assert_not_called()

    @patch("artemis.modules.subdomain_enumeration.http_requests")
    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_wildcard_response_dns_match_http_match(self, mock_lookup: MagicMock, mock_http: MagicMock) -> None:
        """IPs match wildcard AND HTTP content matches baseline → IS wildcard."""
        import hashlib

        body = b"default page"
        body_hash = hashlib.sha256(body).hexdigest()

        mock_lookup.return_value = {"1.2.3.4"}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content_bytes = body
        mock_http.get.return_value = mock_response

        info = WildcardDNSInfo(
            is_wildcard=True,
            wildcard_ips={"1.2.3.4"},
            http_baseline_status=200,
            http_baseline_body_hash=body_hash,
            http_baseline_content_length=len(body),
        )
        self.assertTrue(self.karton._is_wildcard_response("wild.example.com", info))

    @patch("artemis.modules.subdomain_enumeration.http_requests")
    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_wildcard_response_dns_match_http_different(self, mock_lookup: MagicMock, mock_http: MagicMock) -> None:
        """IPs match wildcard BUT HTTP content differs → NOT wildcard (unique vhost)."""
        import hashlib

        baseline_body = b"default page"
        baseline_hash = hashlib.sha256(baseline_body).hexdigest()
        unique_body = b"real application content"

        mock_lookup.return_value = {"1.2.3.4"}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content_bytes = unique_body
        mock_http.get.return_value = mock_response

        info = WildcardDNSInfo(
            is_wildcard=True,
            wildcard_ips={"1.2.3.4"},
            http_baseline_status=200,
            http_baseline_body_hash=baseline_hash,
            http_baseline_content_length=len(baseline_body),
        )
        self.assertFalse(self.karton._is_wildcard_response("real.example.com", info))

    @patch("artemis.modules.subdomain_enumeration.http_requests")
    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_wildcard_response_dns_match_http_different_status(
        self, mock_lookup: MagicMock, mock_http: MagicMock
    ) -> None:
        """IPs match wildcard BUT HTTP status differs → NOT wildcard."""
        import hashlib

        baseline_body = b"default page"
        baseline_hash = hashlib.sha256(baseline_body).hexdigest()

        mock_lookup.return_value = {"1.2.3.4"}
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.content_bytes = baseline_body
        mock_http.get.return_value = mock_response

        info = WildcardDNSInfo(
            is_wildcard=True,
            wildcard_ips={"1.2.3.4"},
            http_baseline_status=200,
            http_baseline_body_hash=baseline_hash,
            http_baseline_content_length=len(baseline_body),
        )
        self.assertFalse(self.karton._is_wildcard_response("different.example.com", info))

    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_wildcard_response_no_http_baseline(self, mock_lookup: MagicMock) -> None:
        """IPs match wildcard, no HTTP baseline (server has no HTTP) → treat as wildcard."""
        mock_lookup.return_value = {"1.2.3.4"}
        info = WildcardDNSInfo(
            is_wildcard=True,
            wildcard_ips={"1.2.3.4"},
        )
        self.assertTrue(self.karton._is_wildcard_response("wild.example.com", info))

    @patch("artemis.modules.subdomain_enumeration.lookup")
    def test_wildcard_response_resolution_failure(self, mock_lookup: MagicMock) -> None:
        """Cannot resolve subdomain → keep it (not wildcard)."""
        from artemis.resolvers import ResolutionException

        mock_lookup.side_effect = ResolutionException("timeout")
        info = WildcardDNSInfo(is_wildcard=True, wildcard_ips={"1.2.3.4"})
        self.assertFalse(self.karton._is_wildcard_response("broken.example.com", info))
