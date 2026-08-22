"""Unit tests for the JS secret pattern registry.

These tests verify that:
  - Known secret formats are correctly detected.
  - Common false-positive inputs are *not* matched.
  - The redaction helper behaves as documented.
"""

import unittest

from artemis.modules.data.js_secrets import SECRET_PATTERNS, SecretPattern
from artemis.modules.js_secret_scanner import JSSecretScanner


class SecretPatternRegistryTest(unittest.TestCase):
    """Ensure every pattern in the registry is a well-formed ``SecretPattern``."""

    def test_all_entries_are_named_tuples(self) -> None:
        for entry in SECRET_PATTERNS:
            self.assertIsInstance(entry, SecretPattern)
            self.assertTrue(entry.name, "Every pattern must have a non-empty name")
            self.assertTrue(entry.description, "Every pattern must have a description")

    def test_no_duplicate_names(self) -> None:
        names = [sp.name for sp in SECRET_PATTERNS]
        self.assertEqual(len(names), len(set(names)), "Duplicate pattern names detected")


class SecretPatternMatchTest(unittest.TestCase):
    """True-positive tests: each known secret format must match."""

    @staticmethod
    def _find_match(pattern_name: str, text: str) -> bool:
        for sp in SECRET_PATTERNS:
            if sp.name == pattern_name:
                return bool(sp.pattern.search(text))
        raise ValueError(f"Pattern '{pattern_name}' not found in SECRET_PATTERNS")

    def test_aws_access_key_id(self) -> None:
        self.assertTrue(self._find_match("AWS Access Key ID", 'key = "AKIA' + '1234567890ABCDEF"'))

    def test_google_api_key(self) -> None:
        self.assertTrue(self._find_match("Google API Key", 'apiKey: "AIza' + 'SyA1234567890abcdefghijklmnopqrstu"'))

    def test_github_token(self) -> None:
        self.assertTrue(self._find_match("GitHub Token", "ghp" + "_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"))

    def test_stripe_live_key(self) -> None:
        self.assertTrue(self._find_match("Stripe API Key", 'sk' + '_live_1234567890abcdef12345678'))

    def test_stripe_test_key(self) -> None:
        self.assertTrue(self._find_match("Stripe API Key", 'sk' + '_test_1234567890abcDEF12345678'))

    def test_slack_token(self) -> None:
        self.assertTrue(self._find_match("Slack Token", "xoxb" + "-1234567890-1234567890-ABCDEFGHIJKLMNOPqrstuvwx"))

    def test_private_key_rsa(self) -> None:
        self.assertTrue(self._find_match("Private Key", "-----BEGIN RSA PRIVATE KEY-----"))

    def test_private_key_ec(self) -> None:
        self.assertTrue(self._find_match("Private Key", "-----BEGIN EC PRIVATE KEY-----"))

    def test_twilio_api_key(self) -> None:
        self.assertTrue(self._find_match("Twilio API Key", "SK" + "1234567890abcdef1234567890abcdef"))


class SecretPatternFalsePositiveTest(unittest.TestCase):
    """False-positive tests: common benign strings must *not* match."""

    @staticmethod
    def _find_match(pattern_name: str, text: str) -> bool:
        for sp in SECRET_PATTERNS:
            if sp.name == pattern_name:
                return bool(sp.pattern.search(text))
        raise ValueError(f"Pattern '{pattern_name}' not found in SECRET_PATTERNS")

    def test_aws_key_too_short(self) -> None:
        self.assertFalse(self._find_match("AWS Access Key ID", "AKIA1234"))

    def test_generic_string_not_github(self) -> None:
        self.assertFalse(self._find_match("GitHub Token", "ghp_short"))

    def test_generic_private_key_header_without_type(self) -> None:
        # Our pattern is intentionally strict — only known key types.
        self.assertFalse(self._find_match("Private Key", "-----BEGIN CERTIFICATE-----"))


class RedactTest(unittest.TestCase):
    """Tests for ``JSSecretScanner._redact``."""

    def test_long_secret(self) -> None:
        result = JSSecretScanner._redact("AKIA1234567890ABCDEF")
        self.assertEqual(result, "AKIA1***REDACTED***CDEF")

    def test_short_secret_fully_redacted(self) -> None:
        result = JSSecretScanner._redact("short")
        self.assertEqual(result, "***REDACTED***")

    def test_boundary_length(self) -> None:
        # Exactly 8 characters → fully redacted (boundary)
        result = JSSecretScanner._redact("12345678")
        self.assertEqual(result, "***REDACTED***")

    def test_nine_characters(self) -> None:
        # 9 characters → prefix/suffix reveal
        result = JSSecretScanner._redact("123456789")
        self.assertEqual(result, "12345***REDACTED***6789")


if __name__ == "__main__":
    unittest.main()
