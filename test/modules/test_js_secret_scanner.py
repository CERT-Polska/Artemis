import unittest
from unittest.mock import MagicMock

from artemis.modules.js_secret_scanner import (
    ENV_VAR_PATTERN,
    FALSE_POSITIVE_VALUES,
    INTERNAL_URL_PATTERN,
    JSSecretScanner,
    MAX_JS_FILES_TO_SCAN,
    SOURCEMAP_COMMENT_PATTERN,
    WEBPACK_CHUNK_PATTERN,
)


class JSSecretScannerUnitTest(unittest.TestCase):
    karton_class = JSSecretScanner  # type: ignore

    def _make_scanner(self) -> JSSecretScanner:
        return JSSecretScanner.__new__(JSSecretScanner)

    def test_is_cdn_exact_domain(self) -> None:
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("cdn.jsdelivr.net", "/npm/jquery.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("cdnjs.cloudflare.com", "/libs/react.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("unpkg.com", "/react@17/umd/react.js"))

    def test_is_cdn_subdomain_matching(self) -> None:
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("cdn2.jsdelivr.net", "/npm/vue.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("cdnjs.cloudflare.com", "/ajax/libs/x.js"))

    def test_is_cdn_vendor_library_detection(self) -> None:
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("example.com", "/js/jquery.min.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("example.com", "/assets/react.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("example.com", "/vendor/angular.min.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("example.com", "/lib/vue.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("example.com", "/js/bootstrap.min.js"))
        self.assertTrue(JSSecretScanner._is_cdn_or_vendor("example.com", "/js/lodash.min.js"))

    def test_is_not_cdn_for_app_code(self) -> None:
        self.assertFalse(JSSecretScanner._is_cdn_or_vendor("example.com", "/app.js"))
        self.assertFalse(JSSecretScanner._is_cdn_or_vendor("static.mysite.com", "/bundle.js"))
        self.assertFalse(JSSecretScanner._is_cdn_or_vendor("cdn.example.com", "/custom.js"))
        self.assertFalse(JSSecretScanner._is_cdn_or_vendor("example.com", "/main.min.js"))

    def test_extract_js_urls_basic(self) -> None:
        scanner = self._make_scanner()
        html = '<html><head><script src="/app.js"></script><script src="/main.js"></script></head></html>'
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://example.com/app.js", urls)
        self.assertIn("https://example.com/main.js", urls)

    def test_extract_js_urls_skips_cdn(self) -> None:
        scanner = self._make_scanner()
        html = '''<html><head>
            <script src="https://cdn.jsdelivr.net/npm/jquery.js"></script>
            <script src="/app.js"></script>
        </head></html>'''
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 1)
        self.assertIn("https://example.com/app.js", urls)

    def test_extract_js_urls_skips_vendor_libraries(self) -> None:
        scanner = self._make_scanner()
        html = '''<html>
            <script src="/js/jquery.min.js"></script>
            <script src="/js/react.js"></script>
            <script src="/app.js"></script>
        </html>'''
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 1)
        self.assertIn("https://example.com/app.js", urls)

    def test_extract_js_urls_resolves_relative(self) -> None:
        scanner = self._make_scanner()
        html = '<html><script src="js/bundle.js"></script></html>'
        urls = scanner._extract_js_urls("https://example.com/page/", html)
        self.assertEqual(len(urls), 1)
        self.assertIn("https://example.com/page/js/bundle.js", urls)

    def test_extract_js_urls_skips_non_http(self) -> None:
        scanner = self._make_scanner()
        html = '<html><script src="data:text/javascript,alert(1)"></script></html>'
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 0)

    def test_extract_js_urls_deduplicates(self) -> None:
        scanner = self._make_scanner()
        html = '<html><script src="/app.js"></script><script src="/app.js"></script></html>'
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 1)

    def test_extract_js_urls_normalizes_fragments_and_query(self) -> None:
        scanner = self._make_scanner()
        html = '''<html>
            <script src="/app.js?v=1.0"></script>
            <script src="/app.js?v=2.0"></script>
            <script src="/app.js#section"></script>
        </html>'''
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 1)

    def test_extract_js_urls_max_limit(self) -> None:
        scanner = self._make_scanner()
        scripts = "".join(f'<script src="/js/file{i}.js"></script>' for i in range(30))
        html = f"<html>{scripts}</html>"
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertLessEqual(len(urls), MAX_JS_FILES_TO_SCAN)

    def test_extract_js_urls_empty_html(self) -> None:
        scanner = self._make_scanner()
        self.assertEqual(scanner._extract_js_urls("https://example.com/", ""), [])

    def test_extract_js_urls_invalid_html(self) -> None:
        scanner = self._make_scanner()
        self.assertEqual(scanner._extract_js_urls("https://example.com/", "<<<not html>>>"), [])

    def test_extract_js_urls_strips_whitespace_src(self) -> None:
        scanner = self._make_scanner()
        html = '<html><script src="  /app.js  "></script></html>'
        urls = scanner._extract_js_urls("https://example.com/", html)
        self.assertEqual(len(urls), 1)

    def test_scan_finds_aws_key(self) -> None:
        scanner = self._make_scanner()
        js = 'var awsKey = "AKIAIOSFODNN7EXAMPLE";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("AWS Access Key ID", names)

    def test_scan_finds_github_token(self) -> None:
        scanner = self._make_scanner()
        js = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("GitHub Token", names)

    def test_scan_finds_github_fine_grained_token(self) -> None:
        scanner = self._make_scanner()
        js = 'const token = "github_pat_ABCDEFGHIJKLMNOPQRSTUVab";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("GitHub Fine-Grained Token", names)

    def test_scan_finds_stripe_secret_key(self) -> None:
        scanner = self._make_scanner()
        js = 'Stripe("' + "sk_" + "live_00TESTFAKE00EXAMPLEKEY00" + '");'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("Stripe Secret Key", names)

    def test_scan_finds_private_key(self) -> None:
        scanner = self._make_scanner()
        js = 'var key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("Private Key", names)

    def test_scan_finds_aws_secret_key(self) -> None:
        scanner = self._make_scanner()
        js = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("AWS Secret Access Key", names)

    def test_scan_finds_sendgrid_key(self) -> None:
        scanner = self._make_scanner()
        js = 'var sg = "SG.FAKEexampleTESTkey0000.FAKEexampleTESTvalue0000000000000000000000000";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("SendGrid API Key", names)

    def test_scan_finds_gitlab_token(self) -> None:
        scanner = self._make_scanner()
        js = 'const token = "glpat-ABCDEFghijklmnopqrst";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("GitLab Token", names)

    def test_scan_finds_shopify_token(self) -> None:
        scanner = self._make_scanner()
        js = 'const token = "shpat_' + "0123456789abcdef0123456789abcdef" + '";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("Shopify Access Token", names)

    def test_scan_finds_discord_webhook(self) -> None:
        scanner = self._make_scanner()
        js = 'var hook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnop";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("Discord Webhook URL", names)

    def test_scan_finds_database_uri(self) -> None:
        scanner = self._make_scanner()
        js = 'const db = "mongodb+srv://user:pass@cluster0.example.mongodb.net/mydb";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("Database Connection URI", names)

    def test_scan_no_secrets_in_clean_code(self) -> None:
        scanner = self._make_scanner()
        js = 'function hello() { console.log("Hello, world!"); }'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        self.assertEqual(len(findings), 0)

    def test_scan_skips_false_positive_values(self) -> None:
        scanner = self._make_scanner()
        js = 'password = "changeme"; api_key = "placeholder";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        self.assertEqual(len(findings), 0)

    def test_scan_skips_single_char_repeated_values(self) -> None:
        scanner = self._make_scanner()
        js = 'password = "aaaaaaaaaa";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        self.assertEqual(len(findings), 0)

    def test_scan_deduplicates_within_file(self) -> None:
        scanner = self._make_scanner()
        js = 'var a = "AKIAIOSFODNN7EXAMPLE"; var b = "AKIAIOSFODNN7EXAMPLE";'
        global_seen: set = set()
        findings = scanner._scan_js_content("https://example.com/app.js", js, global_seen)
        aws_findings = [f for f in findings if f["pattern_name"] == "AWS Access Key ID"]
        self.assertEqual(len(aws_findings), 1)

    def test_scan_deduplicates_across_files(self) -> None:
        scanner = self._make_scanner()
        js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        global_seen: set = set()

        findings1 = scanner._scan_js_content("https://example.com/app.js", js, global_seen)
        findings2 = scanner._scan_js_content("https://example.com/other.js", js, global_seen)

        self.assertTrue(len(findings1) > 0)
        aws_in_second = [f for f in findings2 if f["pattern_name"] == "AWS Access Key ID"]
        self.assertEqual(len(aws_in_second), 0)

    def test_scan_redacts_long_secrets(self) -> None:
        scanner = self._make_scanner()
        js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        for f in findings:
            if f["pattern_name"] == "AWS Access Key ID":
                self.assertIn("...", f["matched_text_redacted"])
                self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f["matched_text_redacted"])

    def test_no_uuid_false_positives(self) -> None:
        scanner = self._make_scanner()
        js = '''
        var sessionId = "550e8400-e29b-41d4-a716-446655440000";
        var trackingId = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        var elementId = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        '''
        findings = scanner._scan_js_content("https://example.com/app.js", js, set())
        self.assertEqual(len(findings), 0)

    def test_firebase_requires_assignment_context(self) -> None:
        scanner = self._make_scanner()

        js_comment = '// See docs at my-project.firebaseio.com for details'
        findings = scanner._scan_js_content("https://example.com/app.js", js_comment, set())
        firebase_findings = [f for f in findings if f["pattern_name"] == "Firebase Database URL"]
        self.assertEqual(len(firebase_findings), 0)

        js_config = 'databaseURL = "https://my-project.firebaseio.com"'
        findings2 = scanner._scan_js_content("https://example.com/app.js", js_config, set())
        firebase_findings2 = [f for f in findings2 if f["pattern_name"] == "Firebase Database URL"]
        self.assertEqual(len(firebase_findings2), 1)

    def test_scan_inline_scripts_finds_secrets(self) -> None:
        scanner = self._make_scanner()
        html = '''<html><body>
            <script>
                // This is application configuration with a hardcoded AWS key
                var config = { awsKey: "AKIAIOSFODNN7EXAMPLE", region: "us-east-1" };
            </script>
        </body></html>'''
        findings = scanner._scan_inline_scripts("https://example.com/", html, set())
        names = [f["pattern_name"] for f in findings]
        self.assertIn("AWS Access Key ID", names)

    def test_scan_inline_scripts_skips_short_scripts(self) -> None:
        scanner = self._make_scanner()
        html = '<html><script>x=1;</script></html>'
        findings = scanner._scan_inline_scripts("https://example.com/", html, set())
        self.assertEqual(len(findings), 0)

    def test_scan_inline_scripts_skips_external_scripts(self) -> None:
        scanner = self._make_scanner()
        html = '<html><script src="/app.js">AKIAIOSFODNN7EXAMPLE</script></html>'
        findings = scanner._scan_inline_scripts("https://example.com/", html, set())
        self.assertEqual(len(findings), 0)

    def test_scan_inline_scripts_labels_with_index(self) -> None:
        scanner = self._make_scanner()
        html = '''<html>
            <script>/* padding to make this script long enough for scanning */ var key1 = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";</script>
            <script>/* padding to make this script long enough for scanning */ var key2 = "''' + "sk_" + "live_00TESTFAKE00EXAMPLEKEY00" + '''";</script>
        </html>'''
        findings = scanner._scan_inline_scripts("https://example.com/", html, set())
        urls = [f["js_url"] for f in findings]
        self.assertTrue(any("inline-0" in u for u in urls))
        self.assertTrue(any("inline-1" in u for u in urls))

    def test_false_positive_set_is_frozen(self) -> None:
        self.assertIsInstance(FALSE_POSITIVE_VALUES, frozenset)

    def test_false_positive_values_are_lowercase(self) -> None:
        for val in FALSE_POSITIVE_VALUES:
            self.assertEqual(val, val.lower())

    # Source map detection tests

    def test_sourcemap_comment_pattern_matches(self) -> None:
        self.assertTrue(SOURCEMAP_COMMENT_PATTERN.search("//# sourceMappingURL=app.js.map"))
        self.assertTrue(SOURCEMAP_COMMENT_PATTERN.search("//@ sourceMappingURL=bundle.js.map"))

    def test_sourcemap_comment_pattern_extracts_url(self) -> None:
        match = SOURCEMAP_COMMENT_PATTERN.search("//# sourceMappingURL=app.js.map")
        self.assertEqual(match.group(1), "app.js.map")

    def test_check_source_map_with_comment(self) -> None:
        scanner = self._make_scanner()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.content = '{"version": 3, "sources": ["app.ts"]}'
        scanner.http_get = MagicMock(return_value=mock_response)

        js_content = 'var x = 1;\n//# sourceMappingURL=app.js.map'
        findings = scanner._check_source_map("https://example.com/app.js", js_content)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern_name"], "Exposed Source Map")

    def test_check_source_map_fallback_probe(self) -> None:
        scanner = self._make_scanner()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.content = '{"version": 3}'
        scanner.http_get = MagicMock(return_value=mock_response)

        js_content = 'var x = 1;'
        findings = scanner._check_source_map("https://example.com/app.js", js_content)
        self.assertEqual(len(findings), 1)

    def test_check_source_map_404_no_finding(self) -> None:
        scanner = self._make_scanner()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.content = "<html>Not Found</html>"
        scanner.http_get = MagicMock(return_value=mock_response)

        js_content = 'var x = 1;'
        findings = scanner._check_source_map("https://example.com/app.js", js_content)
        self.assertEqual(len(findings), 0)

    def test_check_source_map_data_uri_skipped(self) -> None:
        scanner = self._make_scanner()
        scanner.http_get = MagicMock()

        js_content = '//# sourceMappingURL=data:application/json;base64,abc123'
        findings = scanner._check_source_map("https://example.com/app.js", js_content)
        self.assertEqual(len(findings), 0)
        scanner.http_get.assert_not_called()

    # Webpack chunk discovery tests

    def test_webpack_chunk_pattern_matches(self) -> None:
        self.assertTrue(WEBPACK_CHUNK_PATTERN.search('__webpack_require__("./src/app.js")'))
        self.assertTrue(WEBPACK_CHUNK_PATTERN.search('"static/js/chunk-abc123.js"'))
        self.assertTrue(WEBPACK_CHUNK_PATTERN.search('"chunks/vendor.js"'))

    def test_discover_webpack_chunks(self) -> None:
        scanner = self._make_scanner()
        js = '''
        __webpack_require__("./src/utils.js");
        "static/js/chunk-abc.js"
        '''
        chunks = scanner._discover_webpack_chunks("https://example.com/app.js", js)
        self.assertTrue(len(chunks) > 0)

    def test_discover_webpack_chunks_limit(self) -> None:
        scanner = self._make_scanner()
        js = "\n".join(f'"static/js/chunk-{i}.js"' for i in range(20))
        chunks = scanner._discover_webpack_chunks("https://example.com/app.js", js)
        self.assertLessEqual(len(chunks), 5)

    # Environment variable exposure tests

    def test_env_var_pattern_matches(self) -> None:
        self.assertTrue(ENV_VAR_PATTERN.search("process.env.API_KEY"))
        self.assertTrue(ENV_VAR_PATTERN.search("NEXT_PUBLIC_API_URL"))
        self.assertTrue(ENV_VAR_PATTERN.search("REACT_APP_SECRET"))
        self.assertTrue(ENV_VAR_PATTERN.search("VITE_API_KEY"))

    def test_env_var_pattern_skips_node_env(self) -> None:
        self.assertIsNone(ENV_VAR_PATTERN.search("process.env.NODE_ENV"))

    def test_detect_env_var_exposure(self) -> None:
        scanner = self._make_scanner()
        js = 'const url = process.env.API_SECRET_KEY;'
        findings = scanner._detect_env_var_exposure("https://example.com/app.js", js, set())
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["pattern_name"], "Environment Variable Exposure")

    def test_detect_env_var_deduplicates(self) -> None:
        scanner = self._make_scanner()
        js = 'var a = process.env.API_KEY; var b = process.env.API_KEY;'
        global_seen: set = set()
        findings = scanner._detect_env_var_exposure("https://example.com/app.js", js, global_seen)
        self.assertEqual(len(findings), 1)

    # Internal URL detection tests

    def test_internal_url_pattern_matches(self) -> None:
        self.assertTrue(INTERNAL_URL_PATTERN.search("https://api.internal.example.com"))
        self.assertTrue(INTERNAL_URL_PATTERN.search("https://dev.api.example.com"))
        self.assertTrue(INTERNAL_URL_PATTERN.search("https://staging.app.example.com"))
        self.assertTrue(INTERNAL_URL_PATTERN.search("http://localhost:3000"))

    def test_internal_url_pattern_no_false_positive(self) -> None:
        self.assertIsNone(INTERNAL_URL_PATTERN.search("https://www.example.com"))
        self.assertIsNone(INTERNAL_URL_PATTERN.search("https://api.example.com"))

    def test_detect_internal_urls(self) -> None:
        scanner = self._make_scanner()
        js = 'const api = "https://staging.api.example.com/v1";'
        findings = scanner._detect_internal_urls("https://example.com/app.js", js, set())
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["pattern_name"], "Internal URL Exposure")

    def test_detect_internal_urls_deduplicates(self) -> None:
        scanner = self._make_scanner()
        js = 'var a = "http://localhost:8080"; var b = "http://localhost:8080";'
        global_seen: set = set()
        findings = scanner._detect_internal_urls("https://example.com/app.js", js, global_seen)
        self.assertEqual(len(findings), 1)

    # External JS scanning with chunks

    def test_scan_external_js_deduplicates_urls(self) -> None:
        scanner = self._make_scanner()
        mock_response = MagicMock()
        mock_response.content = 'var x = 1;'
        mock_response.headers = {"Content-Type": "application/javascript"}
        mock_response.status_code = 404
        scanner.http_get = MagicMock(return_value=mock_response)

        scanned: set = set()
        scanner._scan_external_js("https://example.com/app.js", set(), scanned)
        first_call_count = scanner.http_get.call_count

        scanner._scan_external_js("https://example.com/app.js", set(), scanned)
        self.assertEqual(scanner.http_get.call_count, first_call_count)
