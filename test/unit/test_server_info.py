#!/usr/bin/env python3
import unittest

from artemis.modules.server_info import (
    build_status_reason,
    classify_header,
    extract_server_info,
    parse_product_token,
)


class TestParseProductToken(unittest.TestCase):
    def test_name_and_version(self) -> None:
        name, version, detail = parse_product_token("Apache/2.4.53")
        self.assertEqual(name, "Apache")
        self.assertEqual(version, "2.4.53")
        self.assertIsNone(detail)

    def test_name_version_detail(self) -> None:
        name, version, detail = parse_product_token("Apache/2.4.53 (Ubuntu)")
        self.assertEqual(name, "Apache")
        self.assertEqual(version, "2.4.53")
        self.assertEqual(detail, "Ubuntu")

    def test_name_only(self) -> None:
        name, version, detail = parse_product_token("nginx")
        self.assertEqual(name, "nginx")
        self.assertIsNone(version)
        self.assertIsNone(detail)

    def test_name_with_version(self) -> None:
        name, version, detail = parse_product_token("nginx/1.18.0")
        self.assertEqual(name, "nginx")
        self.assertEqual(version, "1.18.0")
        self.assertIsNone(detail)

    def test_php_version(self) -> None:
        name, version, detail = parse_product_token("PHP/7.4.3")
        self.assertEqual(name, "PHP")
        self.assertEqual(version, "7.4.3")
        self.assertIsNone(detail)

    def test_aspnet_version(self) -> None:
        name, version, detail = parse_product_token("4.0.30319")
        self.assertEqual(name, "4.0.30319")
        self.assertIsNone(version)
        self.assertIsNone(detail)

    def test_microsoft_iis(self) -> None:
        name, version, detail = parse_product_token("Microsoft-IIS/10.0")
        self.assertEqual(name, "Microsoft-IIS")
        self.assertEqual(version, "10.0")
        self.assertIsNone(detail)

    def test_whitespace_handling(self) -> None:
        name, version, detail = parse_product_token("  Apache/2.4.53  ")
        self.assertEqual(name, "Apache")
        self.assertEqual(version, "2.4.53")


class TestClassifyHeader(unittest.TestCase):
    def test_server_header_classified_as_web_server(self) -> None:
        entry = classify_header("Server", "Apache/2.4.53")
        self.assertEqual(entry["category"], "web_server")
        self.assertEqual(entry["name"], "Apache")
        self.assertEqual(entry["version"], "2.4.53")

    def test_x_powered_by_php_classified_as_language(self) -> None:
        entry = classify_header("X-Powered-By", "PHP/7.4.3")
        self.assertEqual(entry["category"], "programming_language")
        self.assertEqual(entry["name"], "PHP")
        self.assertEqual(entry["version"], "7.4.3")

    def test_x_powered_by_express_classified_as_framework(self) -> None:
        entry = classify_header("X-Powered-By", "Express")
        self.assertEqual(entry["category"], "programming_language")
        self.assertEqual(entry["name"], "Express")

    def test_x_powered_by_unknown_framework(self) -> None:
        entry = classify_header("X-Powered-By", "Phusion Passenger 6.0.4")
        self.assertEqual(entry["category"], "framework")

    def test_x_aspnet_version(self) -> None:
        entry = classify_header("X-AspNet-Version", "4.0.30319")
        self.assertEqual(entry["category"], "framework")

    def test_x_aspnetmvc_version(self) -> None:
        entry = classify_header("X-AspNetMvc-Version", "5.2.7")
        self.assertEqual(entry["category"], "framework")

    def test_x_generator(self) -> None:
        entry = classify_header("X-Generator", "Drupal 9")
        self.assertEqual(entry["category"], "generator")


class TestExtractServerInfo(unittest.TestCase):
    def test_empty_headers(self) -> None:
        results = extract_server_info({})
        self.assertEqual(results, [])

    def test_no_relevant_headers(self) -> None:
        results = extract_server_info({"Content-Type": "text/html", "Date": "Mon, 01 Jan 2024 00:00:00 GMT"})
        self.assertEqual(results, [])

    def test_server_header(self) -> None:
        results = extract_server_info({"Server": "Apache/2.4.53 (Ubuntu)"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "Apache")
        self.assertEqual(results[0]["version"], "2.4.53")
        self.assertEqual(results[0]["detail"], "Ubuntu")
        self.assertEqual(results[0]["category"], "web_server")
        self.assertEqual(results[0]["header"], "Server")

    def test_multiple_headers(self) -> None:
        results = extract_server_info({
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/8.1.2",
        })
        self.assertEqual(len(results), 2)
        categories = {r["category"] for r in results}
        self.assertIn("web_server", categories)
        self.assertIn("programming_language", categories)

    def test_all_header_types(self) -> None:
        results = extract_server_info({
            "Server": "Apache/2.4.53",
            "X-Powered-By": "PHP/8.1.2",
            "X-AspNet-Version": "4.0.30319",
            "X-Generator": "WordPress 6.0",
        })
        self.assertEqual(len(results), 4)
        categories = {r["category"] for r in results}
        self.assertEqual(categories, {"web_server", "programming_language", "framework", "generator"})

    def test_comma_separated_x_powered_by(self) -> None:
        results = extract_server_info({"X-Powered-By": "PHP/7.4, ASP.NET"})
        self.assertEqual(len(results), 2)

    def test_empty_header_value_ignored(self) -> None:
        results = extract_server_info({"Server": ""})
        self.assertEqual(results, [])

    def test_header_field_is_set(self) -> None:
        results = extract_server_info({"Server": "nginx"})
        self.assertEqual(results[0]["header"], "Server")


class TestBuildStatusReason(unittest.TestCase):
    def test_single_detection(self) -> None:
        detected = [{"name": "Apache", "version": "2.4.53", "header": "Server"}]
        reason = build_status_reason(detected)
        self.assertIn("Apache 2.4.53", reason)
        self.assertIn("via Server", reason)

    def test_no_version(self) -> None:
        detected = [{"name": "nginx", "header": "Server"}]
        reason = build_status_reason(detected)
        self.assertIn("nginx", reason)
        self.assertNotIn("None", reason)

    def test_multiple_detections(self) -> None:
        detected = [
            {"name": "Apache", "version": "2.4.53", "header": "Server"},
            {"name": "PHP", "version": "7.4.3", "header": "X-Powered-By"},
        ]
        reason = build_status_reason(detected)
        self.assertIn("Apache 2.4.53", reason)
        self.assertIn("PHP 7.4.3", reason)


class TestExtractServerInfoEdgeCases(unittest.TestCase):
    def test_case_insensitive_language_detection(self) -> None:
        entry = classify_header("X-Powered-By", "php/8.0")
        self.assertEqual(entry["category"], "programming_language")

    def test_servlet_classified_as_language(self) -> None:
        entry = classify_header("X-Powered-By", "Servlet/3.1")
        self.assertEqual(entry["category"], "programming_language")

    def test_aspnet_in_x_powered_by(self) -> None:
        entry = classify_header("X-Powered-By", "ASP.NET")
        self.assertEqual(entry["category"], "programming_language")

    def test_openresty_server(self) -> None:
        results = extract_server_info({"Server": "openresty/1.21.4.1"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "openresty")
        self.assertEqual(results[0]["version"], "1.21.4.1")
        self.assertEqual(results[0]["category"], "web_server")


if __name__ == "__main__":
    unittest.main()
