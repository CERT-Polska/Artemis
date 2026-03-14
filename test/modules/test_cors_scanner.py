import unittest
from unittest.mock import MagicMock

from artemis.modules.cors_scanner import (
    CORSFinding,
    CORSScanner,
    DANGEROUS_METHODS,
    SENSITIVE_HEADERS,
    THIRD_PARTY_TRUST_DOMAINS,
)


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
        self.assertIn("unescaped_dot_bypass", names)
        self.assertIn("underscore_bypass", names)
        self.assertIn("backtick_bypass", names)

        origins = {t["name"]: t["origin"] for t in tests}
        self.assertEqual(origins["arbitrary_origin_reflected"], "https://evil-attacker.com")
        self.assertEqual(origins["null_origin_allowed"], "null")
        self.assertEqual(origins["prefix_match_bypass"], "https://example.com.evil.com")
        self.assertEqual(origins["suffix_match_bypass"], "https://evilexample.com")
        self.assertEqual(origins["subdomain_bypass"], "https://attacker.example.com")
        self.assertEqual(origins["http_scheme_bypass"], "http://example.com")
        self.assertEqual(origins["underscore_bypass"], "https://example.com_.evil.com")
        self.assertEqual(origins["backtick_bypass"], "https://example.com`.evil.com")

    def test_generate_test_origins_http_no_scheme_bypass(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        tests = scanner._generate_test_origins("http://example.com/page")
        names = [t["name"] for t in tests]
        self.assertNotIn("http_scheme_bypass", names)
        self.assertEqual(len(tests), 8)

    def test_generate_test_origins_with_port(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        tests = scanner._generate_test_origins("https://example.com:8443/api")
        origins = {t["name"]: t["origin"] for t in tests}
        self.assertEqual(origins["prefix_match_bypass"], "https://example.com.evil.com")
        self.assertEqual(origins["subdomain_bypass"], "https://attacker.example.com")

    def test_generate_test_origins_unescaped_dot(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        tests = scanner._generate_test_origins("https://example.com/page")
        origins = {t["name"]: t["origin"] for t in tests}
        dot_origin = origins["unescaped_dot_bypass"]
        self.assertIn("evil", dot_origin)
        self.assertNotEqual(dot_origin, "https://evilexample.com")

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

    def test_check_cors_post_finds_reflection(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner.http_post = MagicMock(return_value=mock_response)

        finding = scanner._check_cors_post("https://example.com", "https://evil.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.request_method, "POST")

    def test_check_cors_post_handles_exception(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        scanner.http_post = MagicMock(side_effect=Exception("Timeout"))
        finding = scanner._check_cors_post("https://example.com", "https://evil.com")
        self.assertIsNone(finding)

    def test_check_cors_preflight_finds_reflection(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner._send_options = MagicMock(return_value=mock_response)

        finding = scanner._check_cors_preflight("https://example.com", "https://evil.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.request_method, "OPTIONS")

    def test_check_cors_preflight_handles_none_response(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        scanner._send_options = MagicMock(return_value=None)
        finding = scanner._check_cors_preflight("https://example.com", "https://evil.com")
        self.assertIsNone(finding)

    def test_preflight_dangerous_methods(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Methods": "GET, PUT, DELETE, POST",
        }
        finding = scanner._check_preflight_permissions(headers, "https://evil.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "dangerous_methods_allowed")
        self.assertIn("DELETE", finding.details)
        self.assertIn("PUT", finding.details)

    def test_preflight_safe_methods_only(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        }
        finding = scanner._check_preflight_permissions(headers, "https://evil.com")
        self.assertIsNone(finding)

    def test_preflight_sensitive_headers(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
        }
        finding = scanner._check_preflight_permissions(headers, "https://evil.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "sensitive_headers_allowed")
        self.assertIn("authorization", finding.details)

    def test_preflight_no_acao_returns_none(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Methods": "PUT, DELETE",
        }
        finding = scanner._check_preflight_permissions(headers, "https://evil.com")
        self.assertIsNone(finding)

    def test_preflight_wildcard_acao_checks_methods(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, PUT, PATCH",
        }
        finding = scanner._check_preflight_permissions(headers, "https://evil.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "dangerous_methods_allowed")

    def test_check_vary_origin_missing(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://test-a.example.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner.http_get = MagicMock(return_value=mock_response)

        finding = scanner._check_vary_origin("https://example.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.issue, "missing_vary_origin")
        self.assertIn("cache poisoning", finding.details)

    def test_check_vary_origin_present(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://test-a.example.com",
            "Vary": "Origin, Accept-Encoding",
        }
        scanner.http_get = MagicMock(return_value=mock_response)

        finding = scanner._check_vary_origin("https://example.com")
        self.assertIsNone(finding)

    def test_check_vary_origin_wildcard_skipped(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {"Access-Control-Allow-Origin": "*"}
        scanner.http_get = MagicMock(return_value=mock_response)

        finding = scanner._check_vary_origin("https://example.com")
        self.assertIsNone(finding)

    def test_check_vary_origin_no_reflection(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://trusted.example.com",
        }
        scanner.http_get = MagicMock(return_value=mock_response)

        finding = scanner._check_vary_origin("https://example.com")
        self.assertIsNone(finding)

    def test_check_third_party_trust_found(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)

        def mock_get(url, **kwargs):
            headers = kwargs.get("headers", {})
            origin = headers.get("Origin", "")
            resp = MagicMock()
            if "github.io" in origin:
                resp.headers = {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                }
            else:
                resp.headers = {}
            return resp

        scanner.http_get = mock_get

        findings = scanner._check_third_party_trust("https://example.com")
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].issue, "third_party_domain_trusted")
        self.assertIn("github.io", findings[0].details)

    def test_check_third_party_trust_not_found(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        mock_response = MagicMock()
        mock_response.headers = {"Access-Control-Allow-Origin": "https://trusted.example.com"}
        scanner.http_get = MagicMock(return_value=mock_response)

        findings = scanner._check_third_party_trust("https://example.com")
        self.assertEqual(len(findings), 0)

    def test_check_third_party_trust_handles_exception(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)
        scanner.http_get = MagicMock(side_effect=Exception("Network error"))

        findings = scanner._check_third_party_trust("https://example.com")
        self.assertEqual(len(findings), 0)

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
        self.assertIsNone(finding.details)

    def test_cors_finding_with_details(self) -> None:
        finding = CORSFinding(
            issue="dangerous_methods_allowed",
            origin_sent="https://evil.com",
            acao_header="https://evil.com",
            acac_header=None,
            request_method="OPTIONS",
            details="Methods: DELETE, PUT",
        )
        self.assertEqual(finding.details, "Methods: DELETE, PUT")

    def test_deduplication_across_methods(self) -> None:
        scanner = CORSScanner.__new__(CORSScanner)

        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "https://evil-attacker.com",
            "Access-Control-Allow-Credentials": "true",
        }
        scanner.http_get = MagicMock(return_value=mock_response)
        scanner.http_post = MagicMock(return_value=mock_response)

        seen_issues: set = set()
        findings = []

        origin = "https://evil-attacker.com"
        for check_fn in (scanner._check_cors_simple, scanner._check_cors_post):
            result = check_fn("https://example.com", origin)
            if result:
                key = f"{result.issue}:{result.origin_sent}"
                if key not in seen_issues:
                    seen_issues.add(key)
                    findings.append(result)

        self.assertEqual(len(findings), 1)

    def test_third_party_domains_list_not_empty(self) -> None:
        self.assertTrue(len(THIRD_PARTY_TRUST_DOMAINS) >= 10)

    def test_dangerous_methods_set(self) -> None:
        self.assertIn("PUT", DANGEROUS_METHODS)
        self.assertIn("DELETE", DANGEROUS_METHODS)
        self.assertIn("PATCH", DANGEROUS_METHODS)
        self.assertNotIn("GET", DANGEROUS_METHODS)

    def test_sensitive_headers_set(self) -> None:
        self.assertIn("authorization", SENSITIVE_HEADERS)
        self.assertIn("x-api-key", SENSITIVE_HEADERS)
        self.assertNotIn("content-type", SENSITIVE_HEADERS)
