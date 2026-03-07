import unittest
from unittest.mock import MagicMock

from artemis.modules.cors_scanner import CORSFinding, CORSScanner


class CORSScannerUnitTest(unittest.TestCase):
    karton_class = CORSScanner  # type: ignore

    def test_generate_test_origins_https(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        tests = scanner._generate_test_origins("https://example.com/page")
        names = [t["name"] for t in tests]
        self.assertIn("arbitrary_origin_reflected", names)
        self.assertIn("null_origin_allowed", names)
        self.assertIn("prefix_match_bypass", names)
        self.assertIn("suffix_match_bypass", names)
        self.assertIn("subdomain_bypass", names)
        self.assertIn("http_scheme_bypass", names)

        origins = {t["name"]: t["origin"] for t in tests}
        self.assertEqual(origins["arbitrary_origin_reflected"], "https://evil-attacker.com")
        self.assertEqual(origins["null_origin_allowed"], "null")
        self.assertEqual(origins["prefix_match_bypass"], "https://example.com.evil.com")
        self.assertEqual(origins["suffix_match_bypass"], "https://evilexample.com")
        self.assertEqual(origins["subdomain_bypass"], "https://attacker.example.com")
        self.assertEqual(origins["http_scheme_bypass"], "http://example.com")

    def test_generate_test_origins_http_no_scheme_bypass(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        tests = scanner._generate_test_origins("http://example.com/page")
        names = [t["name"] for t in tests]
        self.assertNotIn("http_scheme_bypass", names)
        self.assertEqual(len(tests), 5)

    def test_generate_test_origins_with_port(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        tests = scanner._generate_test_origins("https://example.com:8443/api")
        origins = {t["name"]: t["origin"] for t in tests}
        self.assertEqual(origins["prefix_match_bypass"], "https://example.com.evil.com")
        self.assertEqual(origins["subdomain_bypass"], "https://attacker.example.com")

    def test_analyze_reflected_origin(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "https://evil-attacker.com",
            "Access-Control-Allow-Credentials": "true",
        }
        finding = scanner._analyze_cors_headers(headers, "https://evil-attacker.com", "GET")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "arbitrary_origin_reflected")
        self.assertEqual(finding.request_method, "GET")

    def test_analyze_wildcard_with_credentials(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        finding = scanner._analyze_cors_headers(headers, "https://evil.com", "GET")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "wildcard_with_credentials")

    def test_analyze_wildcard_without_credentials_is_safe(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {"Access-Control-Allow-Origin": "*"}
        finding = scanner._analyze_cors_headers(headers, "https://evil.com", "GET")
        self.assertIsNone(finding)

    def test_analyze_null_origin_with_credentials(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        }
        finding = scanner._analyze_cors_headers(headers, "null", "OPTIONS")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "null_origin_with_credentials")
        self.assertEqual(finding.request_method, "OPTIONS")

    def test_analyze_null_origin_without_credentials_is_safe(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {"Access-Control-Allow-Origin": "null"}
        finding = scanner._analyze_cors_headers(headers, "null", "GET")
        self.assertIsNone(finding)

    def test_analyze_no_acao_header(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        finding = scanner._analyze_cors_headers({}, "https://evil.com", "GET")
        self.assertIsNone(finding)

    def test_analyze_safe_specific_origin(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {"Access-Control-Allow-Origin": "https://trusted.example.com"}
        finding = scanner._analyze_cors_headers(headers, "https://evil.com", "GET")
        self.assertIsNone(finding)

    def test_analyze_reflected_origin_without_credentials(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {"Access-Control-Allow-Origin": "https://evil.com"}
        finding = scanner._analyze_cors_headers(headers, "https://evil.com", "GET")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "arbitrary_origin_reflected")
        self.assertIsNone(finding.acac_header)

    def test_check_cors_simple_finds_reflection(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil-attacker.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner.http_get = MagicMock(return_value=mock_response)

        finding = scanner._check_cors_simple("https://example.com", "https://evil-attacker.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.request_method, "GET")

    def test_check_cors_simple_handles_exception(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        scanner.http_get = MagicMock(side_effect=Exception("Connection refused"))
        finding = scanner._check_cors_simple("https://example.com", "https://evil.com")
        self.assertIsNone(finding)

    def test_check_cors_preflight_finds_reflection(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner.http_get = MagicMock(return_value=mock_response)

        finding = scanner._check_cors_preflight("https://example.com", "https://evil.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.request_method, "OPTIONS")

        call_kwargs = scanner.http_get.call_args
        sent_headers = call_kwargs.kwargs.get("headers", {}) if call_kwargs.kwargs else call_kwargs[1].get("headers", {})
        self.assertIn("Access-Control-Request-Method", sent_headers)
        self.assertIn("Access-Control-Request-Headers", sent_headers)

    def test_check_cors_preflight_handles_exception(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        scanner.http_get = MagicMock(side_effect=Exception("Timeout"))
        finding = scanner._check_cors_preflight("https://example.com", "https://evil.com")
        self.assertIsNone(finding)

    def test_cors_finding_dataclass(self) -> None:
        finding = CORSFinding(
            issue="arbitrary_origin_reflected",
            origin_sent="https://evil.com",
            acao_header="https://evil.com",
            acac_header="true",
            request_method="GET",
        )
        self.assertEqual(finding.issue, "arbitrary_origin_reflected")
        self.assertEqual(finding.request_method, "GET")

    def test_deduplication_across_simple_and_preflight(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)

        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil-attacker.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner.http_get = MagicMock(return_value=mock_response)

        seen_issues: set = set()
        findings = []

        origin = "https://evil-attacker.com"
        simple = scanner._check_cors_simple("https://example.com", origin)
        if simple:
            key = f"{simple.issue}:{simple.origin_sent}"
            if key not in seen_issues:
                seen_issues.add(key)
                findings.append(simple)

        preflight = scanner._check_cors_preflight("https://example.com", origin)
        if preflight:
            key = f"{preflight.issue}:{preflight.origin_sent}"
            if key not in seen_issues:
                seen_issues.add(key)
                findings.append(preflight)

        self.assertEqual(len(findings), 1)
