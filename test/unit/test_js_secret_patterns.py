import unittest

from artemis.modules.data.js_secret_patterns import SECRET_PATTERNS


class JSSecretPatternsTest(unittest.TestCase):
    def _find_pattern(self, name: str):
        for p in SECRET_PATTERNS:
            if p.name == name:
                return p
        self.fail(f"Pattern '{name}' not found in SECRET_PATTERNS")

    def test_aws_access_key_matches(self) -> None:
        pattern = self._find_pattern("AWS Access Key ID")
        # AKIA + 16 uppercase alphanumeric = 20 chars, needs non-alnum boundary
        self.assertTrue(pattern.regex.search('"AKIAIOSFODNN7EXAMPLE"'))
        self.assertTrue(pattern.regex.search('var key = "ASIA1234567890ABCDEF";'))

    def test_aws_access_key_rejects_short(self) -> None:
        pattern = self._find_pattern("AWS Access Key ID")
        self.assertIsNone(pattern.regex.search("AKIASHORT"))

    def test_aws_access_key_rejects_embedded(self) -> None:
        pattern = self._find_pattern("AWS Access Key ID")
        self.assertIsNone(pattern.regex.search("abcAKIAIOSFODNN7EXAMPLExyz"))

    def test_aws_secret_key_matches(self) -> None:
        pattern = self._find_pattern("AWS Secret Access Key")
        self.assertTrue(pattern.regex.search(
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"'
        ))
        self.assertTrue(pattern.regex.search(
            "AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1'"
        ))

    def test_aws_secret_key_rejects_bare_string(self) -> None:
        pattern = self._find_pattern("AWS Secret Access Key")
        self.assertIsNone(pattern.regex.search("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1"))

    def test_google_api_key_matches(self) -> None:
        pattern = self._find_pattern("Google API Key")
        self.assertTrue(pattern.regex.search("AIzaSyA1234567890abcdefghijklmnopqrstuv"))

    def test_google_api_key_rejects_short(self) -> None:
        pattern = self._find_pattern("Google API Key")
        self.assertIsNone(pattern.regex.search("AIzaShort"))

    def test_google_oauth_secret_matches(self) -> None:
        pattern = self._find_pattern("Google OAuth Secret")
        self.assertTrue(pattern.regex.search("GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ01"))

    def test_google_oauth_secret_rejects_wrong_prefix(self) -> None:
        pattern = self._find_pattern("Google OAuth Secret")
        self.assertIsNone(pattern.regex.search("GOCSXX-abcdefghijklmnopqrstuvwxyz"))

    def test_slack_token_matches(self) -> None:
        pattern = self._find_pattern("Slack Token")
        self.assertTrue(pattern.regex.search("xoxb-1234567890-1234567890-abcdef"))
        self.assertTrue(pattern.regex.search("xoxp-1234567890-1234567890-token"))

    def test_slack_token_rejects_short(self) -> None:
        pattern = self._find_pattern("Slack Token")
        self.assertIsNone(pattern.regex.search("xoxb-short"))

    def test_slack_webhook_matches(self) -> None:
        pattern = self._find_pattern("Slack Webhook URL")
        # Built dynamically to avoid GitHub push protection false positive
        webhook = "https://hooks.slack.com/services/" + "TEXAMPLE1" + "/BEXAMPLE1" + "/FAKE0example0webhook0key"
        self.assertTrue(pattern.regex.search(webhook))

    def test_slack_webhook_rejects_wrong_domain(self) -> None:
        pattern = self._find_pattern("Slack Webhook URL")
        webhook = "https://hooks.notslack.com/services/" + "TEXAMPLE1" + "/BEXAMPLE1" + "/FAKE0example0webhook0key"
        self.assertIsNone(pattern.regex.search(webhook))

    def test_github_token_matches(self) -> None:
        pattern = self._find_pattern("GitHub Token")
        self.assertTrue(pattern.regex.search("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))
        self.assertTrue(pattern.regex.search("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))

    def test_github_token_rejects_short(self) -> None:
        pattern = self._find_pattern("GitHub Token")
        self.assertIsNone(pattern.regex.search("ghp_short"))

    def test_github_fine_grained_token_matches(self) -> None:
        pattern = self._find_pattern("GitHub Fine-Grained Token")
        self.assertTrue(pattern.regex.search("github_pat_ABCDEFGHIJKLMNOPQRSTUVab"))

    def test_github_fine_grained_token_rejects_wrong_prefix(self) -> None:
        pattern = self._find_pattern("GitHub Fine-Grained Token")
        self.assertIsNone(pattern.regex.search("github_xxx_ABCDEFGHIJKLMNOPQRSTUVab"))

    def test_stripe_secret_key_matches(self) -> None:
        pattern = self._find_pattern("Stripe Secret Key")
        # Built dynamically to avoid GitHub push protection false positive
        self.assertTrue(pattern.regex.search("sk_" + "live_00TESTFAKE00EXAMPLEKEY00"))
        self.assertTrue(pattern.regex.search("sk_" + "test_00TESTFAKE00EXAMPLEKEY00"))

    def test_stripe_secret_key_rejects_publishable(self) -> None:
        pattern = self._find_pattern("Stripe Secret Key")
        self.assertIsNone(pattern.regex.search("pk_" + "live_00TESTFAKE00EXAMPLEKEY00"))

    def test_stripe_secret_key_rejects_short(self) -> None:
        pattern = self._find_pattern("Stripe Secret Key")
        self.assertIsNone(pattern.regex.search("sk_live_short"))

    def test_stripe_publishable_key_matches(self) -> None:
        pattern = self._find_pattern("Stripe Publishable Key")
        self.assertTrue(pattern.regex.search("pk_" + "live_00TESTFAKE00EXAMPLEKEY00"))
        self.assertTrue(pattern.regex.search("pk_" + "test_00TESTFAKE00EXAMPLEKEY00"))

    def test_sendgrid_key_matches(self) -> None:
        pattern = self._find_pattern("SendGrid API Key")
        self.assertTrue(pattern.regex.search(
            "SG.FAKEexampleTESTkey0000.FAKEexampleTESTvalue0000000000000000000000000"
        ))

    def test_sendgrid_key_rejects_wrong_format(self) -> None:
        pattern = self._find_pattern("SendGrid API Key")
        self.assertIsNone(pattern.regex.search("SG.short.short"))

    def test_twilio_key_matches(self) -> None:
        pattern = self._find_pattern("Twilio API Key")
        self.assertTrue(pattern.regex.search("SK00000000face00e0a00000000000beef"))

    def test_twilio_key_rejects_short(self) -> None:
        pattern = self._find_pattern("Twilio API Key")
        self.assertIsNone(pattern.regex.search("SK1234"))

    def test_mailgun_key_matches(self) -> None:
        pattern = self._find_pattern("Mailgun API Key")
        self.assertTrue(pattern.regex.search("key-1234567890abcdef1234567890abcdef"))

    def test_mailgun_key_rejects_short(self) -> None:
        pattern = self._find_pattern("Mailgun API Key")
        self.assertIsNone(pattern.regex.search("key-short"))

    def test_private_key_matches(self) -> None:
        pattern = self._find_pattern("Private Key")
        self.assertTrue(pattern.regex.search("-----BEGIN RSA PRIVATE KEY-----"))
        self.assertTrue(pattern.regex.search("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pattern.regex.search("-----BEGIN EC PRIVATE KEY-----"))
        self.assertTrue(pattern.regex.search("-----BEGIN OPENSSH PRIVATE KEY-----"))

    def test_private_key_rejects_public(self) -> None:
        pattern = self._find_pattern("Private Key")
        self.assertIsNone(pattern.regex.search("-----BEGIN PUBLIC KEY-----"))
        self.assertIsNone(pattern.regex.search("-----BEGIN CERTIFICATE-----"))

    def test_jwt_matches(self) -> None:
        pattern = self._find_pattern("JSON Web Token")
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertTrue(pattern.regex.search(jwt))

    def test_jwt_rejects_short_segments(self) -> None:
        pattern = self._find_pattern("JSON Web Token")
        self.assertIsNone(pattern.regex.search("eyJshort.eyJshort.short"))

    def test_firebase_url_matches_with_context(self) -> None:
        pattern = self._find_pattern("Firebase Database URL")
        self.assertTrue(pattern.regex.search('databaseURL = "https://my-project.firebaseio.com"'))
        self.assertTrue(pattern.regex.search("firebase_url: 'https://app.firebaseio.com/'"))

    def test_firebase_url_rejects_bare_url(self) -> None:
        pattern = self._find_pattern("Firebase Database URL")
        self.assertIsNone(pattern.regex.search("my-project.firebaseio.com"))
        self.assertIsNone(pattern.regex.search("// visit my-project.firebaseio.com"))

    def test_bearer_token_matches(self) -> None:
        pattern = self._find_pattern("Hardcoded Bearer Token")
        self.assertTrue(pattern.regex.search('"Bearer eyJhbGciOiJIUzI1NiJ9token"'))
        self.assertTrue(pattern.regex.search("'bearer abcdefghijklmnopqrst1234'"))

    def test_bearer_token_rejects_without_quotes(self) -> None:
        pattern = self._find_pattern("Hardcoded Bearer Token")
        self.assertIsNone(pattern.regex.search("Bearer abcdefghijklmnopqrst1234"))

    def test_hardcoded_password_matches(self) -> None:
        pattern = self._find_pattern("Hardcoded Password")
        self.assertTrue(pattern.regex.search('password = "supersecretpassword123"'))
        self.assertTrue(pattern.regex.search("api_key: 'my-secret-api-key-value'"))
        self.assertTrue(pattern.regex.search('apikey = "longapikey12345678"'))
        self.assertTrue(pattern.regex.search('access_token = "abcdefghijklmnop"'))

    def test_hardcoded_password_rejects_short_value(self) -> None:
        pattern = self._find_pattern("Hardcoded Password")
        self.assertIsNone(pattern.regex.search('password = "short"'))

    def test_hardcoded_password_rejects_no_context(self) -> None:
        pattern = self._find_pattern("Hardcoded Password")
        self.assertIsNone(pattern.regex.search('var name = "supersecretpassword123"'))

    def test_no_uuid_pattern_exists(self) -> None:
        names = [p.name for p in SECRET_PATTERNS]
        self.assertNotIn("Heroku API Key", names)

    def test_all_patterns_have_valid_severity(self) -> None:
        for pattern in SECRET_PATTERNS:
            self.assertIn(pattern.severity, ("high", "medium"))

    def test_all_patterns_have_compiled_regex(self) -> None:
        for pattern in SECRET_PATTERNS:
            self.assertIsNotNone(pattern.regex)
            self.assertTrue(hasattr(pattern.regex, "search"))

    def test_all_pattern_names_are_unique(self) -> None:
        names = [p.name for p in SECRET_PATTERNS]
        self.assertEqual(len(names), len(set(names)))

    def test_pattern_count(self) -> None:
        self.assertGreaterEqual(len(SECRET_PATTERNS), 15)
        self.assertLessEqual(len(SECRET_PATTERNS), 30)
