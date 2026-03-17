import unittest

from artemis.waf_bypass import (
    WAF_STRATEGIES,
    add_fake_path_info,
    add_noise_params,
    add_random_comments,
    apostrophe_to_double_unicode,
    apostrophe_to_utf8_fullwidth,
    apply_bypass,
    backslash_traversal,
    base64_encode,
    between_encode,
    concat_encode,
    content_type_charset_bypass,
    dot_double_encode,
    dot_segment_abuse,
    double_url_encode,
    equal_to_like,
    get_bypass_payloads,
    get_ssrf_ip_variants,
    hex_encode_string,
    html_entity_encode,
    html_entity_hex_encode,
    http_parameter_pollution,
    ibm037_encode,
    ip_to_decimal,
    ip_to_hex,
    ip_to_ipv6_compressed,
    ip_to_ipv6_mapped,
    ip_to_octal,
    localhost_alternatives,
    mixed_case,
    mixed_slash_traversal,
    multiple_spaces,
    mysql_inline_comment,
    mysql_versioned_comment,
    non_recursive_replacement,
    null_byte_inject,
    path_double_slash,
    percentage_encode,
    randomize_header_case,
    space_to_inline_comment,
    space_to_multiline_comment,
    space_to_newline,
    space_to_plus,
    space_to_tab,
    ssrf_url_encode,
    unicode_encode,
    unicode_fullwidth_dot,
    unicode_fullwidth_slash,
    url_encode,
    utf8_overlong_dot,
)
from artemis.waf_detect import WAFInfo, WAFType


class TestEncodingTransforms(unittest.TestCase):
    def test_url_encoding(self) -> None:
        self.assertEqual(url_encode("sleep(5)"), "sleep%285%29")
        self.assertEqual(url_encode("'\""), "%27%22")
        self.assertEqual(url_encode("UNION SELECT"), "UNION%20SELECT")

    def test_double_url_encoding(self) -> None:
        self.assertIn("%25", double_url_encode("sleep(5)"))
        self.assertIn("%25", double_url_encode("../etc/passwd"))

    def test_unicode_encoding(self) -> None:
        self.assertEqual(unicode_encode("AB"), "%u0041%u0042")
        self.assertEqual(unicode_encode("'"), "%u0027")

    def test_html_entity_encoding(self) -> None:
        self.assertEqual(html_entity_encode("<script>"), "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;")
        self.assertEqual(html_entity_hex_encode("<"), "&#x3c;")

    def test_other_encoding(self) -> None:
        self.assertEqual(hex_encode_string("test"), "0x74657374")
        self.assertEqual(base64_encode("alert(1)"), "YWxlcnQoMSk=")

    def test_case_manipulation(self) -> None:
        self.assertEqual(mixed_case("select"), "sElEcT")
        result = mixed_case("a1b2")
        self.assertIn("1", result)
        self.assertIn("2", result)


class TestSQLTransforms(unittest.TestCase):
    def test_space_replacements(self) -> None:
        self.assertEqual(space_to_inline_comment("UNION SELECT"), "UNION/**/SELECT")
        self.assertEqual(space_to_plus("UNION SELECT"), "UNION+SELECT")
        self.assertEqual(space_to_newline("UNION SELECT"), "UNION%0aSELECT")
        self.assertEqual(space_to_tab("UNION SELECT"), "UNION%09SELECT")

        result = space_to_multiline_comment("UNION SELECT")
        self.assertIn("/*", result)
        self.assertIn("*/", result)
        self.assertNotIn(" ", result)

    def test_mysql_comments(self) -> None:
        self.assertEqual(mysql_inline_comment("sleep(5)"), "/*!sleep*/(5)")
        self.assertEqual(mysql_inline_comment("SELECT"), "/*!SELECT*/")
        self.assertRegex(mysql_versioned_comment("sleep(5)"), r"/\*!\d{5}sleep\*/\(5\)")

    def test_sql_keyword_transforms(self) -> None:
        self.assertIn("NOT BETWEEN", between_encode("1>0"))
        self.assertEqual(equal_to_like("id=1"), "id LIKE 1")
        self.assertIn("CONCAT(", concat_encode("sleep"))
        self.assertEqual(concat_encode("ab"), "ab")
        self.assertEqual(apostrophe_to_utf8_fullwidth("'test'"), "%EF%BC%87test%EF%BC%87")
        self.assertEqual(apostrophe_to_double_unicode("'test"), "%00%27test")
        self.assertEqual(percentage_encode("SELECT"), "%S%E%L%E%C%T")

    def test_space_and_keyword_manipulation(self) -> None:
        self.assertGreater(len(multiple_spaces("A B")), 3)

        result = non_recursive_replacement("SELECT")
        self.assertIn("SELECT", result)
        self.assertGreater(len(result), 6)

        result = add_random_comments("SELECT")
        self.assertIn("S", result)


class TestPathTraversalTransforms(unittest.TestCase):
    def test_encoding_variants(self) -> None:
        self.assertEqual(dot_double_encode("../../etc/passwd"), "%252e%252e%252f%252e%252e%252fetc/passwd")
        self.assertEqual(dot_double_encode("..\\..\\windows\\win.ini"), "%252e%252e%255c%252e%252e%255cwindows\\win.ini")
        self.assertEqual(utf8_overlong_dot("../../etc/passwd"), "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd")
        self.assertEqual(null_byte_inject("../../etc/passwd"), "../../etc/passwd%00")
        self.assertEqual(path_double_slash("../../etc/passwd"), "..../..../etc/passwd")
        self.assertEqual(backslash_traversal("../../etc/passwd"), "..\\..\\etc/passwd")

    def test_slash_and_dot_variants(self) -> None:
        self.assertIn("\\", mixed_slash_traversal("../../etc/passwd"))
        self.assertIn("/./", dot_segment_abuse("../../etc/passwd"))

        result = unicode_fullwidth_slash("../../etc/passwd")
        self.assertIn("%ef%bc%8f", result)
        self.assertNotIn("/", result)

        self.assertIn("%ef%bc%8e", unicode_fullwidth_dot("../../etc/passwd"))


class TestSSRFTransforms(unittest.TestCase):
    def test_ip_conversions(self) -> None:
        self.assertEqual(ip_to_decimal("127.0.0.1"), "2130706433")
        self.assertEqual(ip_to_decimal("169.254.169.254"), "2852039166")
        self.assertEqual(ip_to_hex("127.0.0.1"), "0x7f000001")
        self.assertIn("0177", ip_to_octal("127.0.0.1"))
        self.assertEqual(ip_to_ipv6_mapped("127.0.0.1"), "[::ffff:127.0.0.1]")

        result = ip_to_ipv6_compressed("127.0.0.1")
        self.assertIn("ffff", result)
        self.assertIn("7f00", result)

    def test_localhost_and_metadata_alternatives(self) -> None:
        self.assertNotEqual(localhost_alternatives("http://127.0.0.1/test"), "http://127.0.0.1/test")
        self.assertNotEqual(
            localhost_alternatives("http://169.254.169.254/latest/meta-data/"),
            "http://169.254.169.254/latest/meta-data/",
        )
        self.assertIn("%3A%2F%2F", ssrf_url_encode("http://127.0.0.1/test"))

    def test_ip_variant_generation(self) -> None:
        variants = get_ssrf_ip_variants("127.0.0.1")
        self.assertIn("127.0.0.1", variants)
        self.assertIn("2130706433", variants)
        self.assertIn("0x7f000001", variants)
        self.assertIn("[::ffff:127.0.0.1]", variants)
        self.assertGreater(len(variants), 5)
        self.assertEqual(len(variants), len(set(variants)))

        variants = get_ssrf_ip_variants("169.254.169.254")
        self.assertIn("2852039166", variants)
        self.assertGreater(len(variants), 4)


class TestHTTPEvasion(unittest.TestCase):
    def test_header_and_url_manipulation(self) -> None:
        headers = {"Content-Type": "text/html", "Accept": "application/json"}
        result = randomize_header_case(headers)
        self.assertEqual(len(result), 2)
        self.assertIn("text/html", result.values())

        self.assertIn("?", add_noise_params("http://example.com"))
        self.assertIn("&", add_noise_params("http://example.com?id=1"))
        self.assertIn("/..", add_fake_path_info("http://example.com/page.php?id=1"))
        self.assertEqual(add_fake_path_info("http://example.com/page.php"), "http://example.com/page.php")

    def test_parameter_pollution_and_charset(self) -> None:
        result = http_parameter_pollution("http://example.com", "id", "1 OR 1=1")
        self.assertIn("id=safe", result)
        self.assertIn("id=1 OR 1=1", result)

        headers = content_type_charset_bypass("ibm037")
        self.assertIn("charset=ibm037", headers["Content-Type"])
        self.assertNotEqual(ibm037_encode("test"), "test")


class TestBypassPayloadGeneration(unittest.TestCase):
    def test_no_waf(self) -> None:
        self.assertEqual(get_bypass_payloads("sleep(5)"), ["sleep(5)"])
        waf_info = WAFInfo(detected=False, waf_type=WAFType.UNKNOWN, confidence="low", evidence="")
        self.assertEqual(get_bypass_payloads("sleep(5)", waf_info), ["sleep(5)"])
        self.assertEqual(apply_bypass("sleep(5)"), "sleep(5)")

    def test_waf_specific_payloads(self) -> None:
        cf_info = WAFInfo(detected=True, waf_type=WAFType.CLOUDFLARE, confidence="high", evidence="cf-ray")
        result = get_bypass_payloads("sleep(5)", cf_info, context="sqli")
        self.assertGreater(len(result), 1)
        self.assertEqual(result[0], "sleep(5)")
        self.assertEqual(len(result), len(set(result)))

        ms_info = WAFInfo(detected=True, waf_type=WAFType.MODSECURITY, confidence="high", evidence="ModSecurity")
        self.assertIn("/*!sleep*/(5)", get_bypass_payloads("sleep(5)", ms_info, context="sqli"))

    def test_apply_bypass_transforms(self) -> None:
        cf_info = WAFInfo(detected=True, waf_type=WAFType.CLOUDFLARE, confidence="high", evidence="cf-ray")
        self.assertNotEqual(apply_bypass("sleep(5)", cf_info, context="sqli"), "sleep(5)")
        self.assertNotEqual(apply_bypass("../../etc/passwd", cf_info, context="lfi"), "../../etc/passwd")
        self.assertNotEqual(apply_bypass("' OR 1=1--", cf_info, context="generic"), "' OR 1=1--")
        self.assertNotEqual(apply_bypass("http://169.254.169.254/latest/", cf_info, context="ssrf"),
                            "http://169.254.169.254/latest/")

        ms_info = WAFInfo(detected=True, waf_type=WAFType.MODSECURITY, confidence="high", evidence="mod")
        self.assertEqual(apply_bypass("sleep(5)", ms_info, context="sqli"), "/*!sleep*/(5)")

        aws_info = WAFInfo(detected=True, waf_type=WAFType.AWS_WAF, confidence="high", evidence="waf")
        self.assertIn("%u", apply_bypass("sleep(5)", aws_info, context="sqli"))

    def test_all_waf_strategies_produce_variants(self) -> None:
        payloads = {
            "sqli": "sleep(5)",
            "lfi": "../../etc/passwd",
            "xss": "<script>alert(1)</script>",
            "crlf": "%0d%0aSet-Cookie: evil=1",
            "ssrf": "http://169.254.169.254/latest/meta-data/",
            "generic": "' OR 1=1--",
        }
        for waf_type in WAF_STRATEGIES:
            waf_info = WAFInfo(detected=True, waf_type=waf_type, confidence="high", evidence="test")
            for context, payload in payloads.items():
                result = get_bypass_payloads(payload, waf_info, context=context)
                self.assertGreater(len(result), 1, f"No variants for {waf_type.value}/{context}")

    def test_unknown_waf_uses_defaults(self) -> None:
        waf_info = WAFInfo(detected=True, waf_type=WAFType.UNKNOWN, confidence="medium", evidence="403")
        self.assertGreater(len(get_bypass_payloads("sleep(5)", waf_info, context="sqli")), 1)


if __name__ == "__main__":
    unittest.main()
