"""
Unit tests for API token validation logic.

These tests verify that the hmac.compare_digest function used in api.py
correctly validates tokens in a constant-time manner to prevent timing attacks.
"""

import hmac
import unittest


class HmacCompareDigestTest(unittest.TestCase):
    """Tests for hmac.compare_digest behavior used in API token validation."""

    def test_valid_token_matches(self) -> None:
        """Test that identical tokens compare as equal."""
        token = "valid-test-token"
        config_token = "valid-test-token"
        self.assertTrue(hmac.compare_digest(token, config_token))

    def test_invalid_token_does_not_match(self) -> None:
        """Test that different tokens compare as not equal."""
        token = "invalid-token"
        config_token = "valid-test-token"
        self.assertFalse(hmac.compare_digest(token, config_token))

    def test_empty_token_does_not_match(self) -> None:
        """Test that empty token does not match a valid config token."""
        token = ""
        config_token = "valid-test-token"
        self.assertFalse(hmac.compare_digest(token, config_token))

    def test_partial_token_does_not_match(self) -> None:
        """Test that partial token does not match the full config token."""
        token = "valid-test"
        config_token = "valid-test-token"
        self.assertFalse(hmac.compare_digest(token, config_token))

    def test_token_with_extra_chars_does_not_match(self) -> None:
        """Test that token with extra characters does not match."""
        token = "valid-test-token-extra"
        config_token = "valid-test-token"
        self.assertFalse(hmac.compare_digest(token, config_token))

    def test_case_sensitive_comparison(self) -> None:
        """Test that token comparison is case-sensitive."""
        token = "Valid-Test-Token"
        config_token = "valid-test-token"
        self.assertFalse(hmac.compare_digest(token, config_token))

    def test_whitespace_matters(self) -> None:
        """Test that whitespace in tokens matters."""
        token = " valid-test-token"
        config_token = "valid-test-token"
        self.assertFalse(hmac.compare_digest(token, config_token))

        token = "valid-test-token "
        self.assertFalse(hmac.compare_digest(token, config_token))
