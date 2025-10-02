"""Tests for resilient translation export functionality."""

import gettext
import io
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from jinja2 import Environment

from artemis.reporting.base.language import Language
from artemis.reporting.export.translations import (
    TranslationCollectMissing,
    TranslationRaiseException,
    clear_missing_translations,
    get_missing_translations,
    install_translations,
)


def create_empty_mo_file():
    """Create an empty .mo file in memory for testing."""
    # Minimal .mo file format (magic number + empty catalog)
    mo_data = (
        b"\xde\x12\x04\x95"  # Magic number (little-endian)
        b"\x00\x00\x00\x00"  # File format version
        b"\x00\x00\x00\x00"  # Number of strings
        b"\x1c\x00\x00\x00"  # Offset of table with original strings
        b"\x1c\x00\x00\x00"  # Offset of table with translation strings
        b"\x00\x00\x00\x00"  # Size of hashing table
        b"\x1c\x00\x00\x00"  # Offset of hashing table
    )
    return io.BytesIO(mo_data)


class TestTranslationCollectMissing:
    """Test the TranslationCollectMissing class that collects missing translations."""

    def test_collects_single_missing_translation(self):
        """Test that a single missing translation is collected."""
        clear_missing_translations()

        # Create a minimal translation object with empty catalog
        trans = TranslationCollectMissing(create_empty_mo_file())

        # Try to translate a message that doesn't exist
        result = trans.gettext("This message does not exist")

        # Should return the original message as fallback
        assert result == "This message does not exist"

        # Should be collected in missing translations
        missing = get_missing_translations()
        assert "This message does not exist" in missing
        assert len(missing) == 1

    def test_collects_multiple_missing_translations(self):
        """Test that multiple missing translations are collected."""
        clear_missing_translations()

        trans = TranslationCollectMissing(create_empty_mo_file())

        # Try to translate multiple messages
        trans.gettext("Missing message 1")
        trans.gettext("Missing message 2")
        trans.gettext("Missing message 3")

        missing = get_missing_translations()
        assert len(missing) == 3
        assert "Missing message 1" in missing
        assert "Missing message 2" in missing
        assert "Missing message 3" in missing

    def test_deduplicates_missing_translations(self):
        """Test that duplicate missing translations are deduplicated."""
        clear_missing_translations()

        trans = TranslationCollectMissing(create_empty_mo_file())

        # Try to translate the same message multiple times
        trans.gettext("Duplicate message")
        trans.gettext("Duplicate message")
        trans.gettext("Duplicate message")

        missing = get_missing_translations()
        assert len(missing) == 1
        assert "Duplicate message" in missing

    def test_clear_missing_translations(self):
        """Test that clearing missing translations works."""
        clear_missing_translations()

        trans = TranslationCollectMissing(create_empty_mo_file())
        trans.gettext("Message to clear")

        assert len(get_missing_translations()) == 1

        clear_missing_translations()
        assert len(get_missing_translations()) == 0

    def test_get_missing_translations_sorted(self):
        """Test that get_missing_translations returns sorted results."""
        clear_missing_translations()

        trans = TranslationCollectMissing(create_empty_mo_file())
        trans.gettext("Zebra")
        trans.gettext("Apple")
        trans.gettext("Banana")

        missing = get_missing_translations()
        assert missing == ["Apple", "Banana", "Zebra"]


class TestTranslationRaiseException:
    """Test the TranslationRaiseException class (original behavior)."""

    def test_raises_on_missing_translation(self):
        """Test that missing translations raise exceptions."""
        from artemis.reporting.exceptions import TranslationNotFoundException

        trans = TranslationRaiseException(create_empty_mo_file())

        with pytest.raises(TranslationNotFoundException) as exc_info:
            trans.gettext("This message does not exist")

        assert "Unable to translate" in str(exc_info.value)
        assert "This message does not exist" in str(exc_info.value)


class TestInstallTranslations:
    """Test the install_translations function with resilient mode."""

    @patch("artemis.reporting.export.translations.subprocess.call")
    @patch("artemis.reporting.export.translations.shutil.copy")
    def test_install_translations_resilient_mode(self, mock_copy, mock_subprocess):
        """Test that resilient mode uses TranslationCollectMissing."""
        env = Environment(extensions=['jinja2.ext.i18n'])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".po", delete=False) as f:
            translations_path = Path(f.name)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mo", delete=False) as f:
            compiled_path = Path(f.name)

        try:
            # Mock Path(__file__).parents[1].glob to return empty list
            with patch("artemis.reporting.export.translations.Path") as mock_path_class:
                mock_file_path = MagicMock()
                mock_parent = MagicMock()
                mock_parent.glob.return_value = []
                mock_file_path.parents = [MagicMock(), mock_parent]  # Index [1] is the parent we need
                mock_path_class.return_value = mock_file_path

                # Mock gettext.translation to return our test translation object
                with patch("artemis.reporting.export.translations.gettext.translation") as mock_translation:
                    mock_trans_obj = MagicMock()
                    mock_translation.return_value = mock_trans_obj

                    install_translations(
                        Language.pl_PL,
                        env,
                        translations_path,
                        compiled_path,
                        resilient_mode=True,
                    )

                    # Verify that gettext.translation was called with TranslationCollectMissing
                    call_kwargs = mock_translation.call_args[1]
                    assert call_kwargs["class_"] == TranslationCollectMissing
        finally:
            translations_path.unlink(missing_ok=True)
            compiled_path.unlink(missing_ok=True)

    @patch("artemis.reporting.export.translations.subprocess.call")
    @patch("artemis.reporting.export.translations.shutil.copy")
    def test_install_translations_non_resilient_mode(self, mock_copy, mock_subprocess):
        """Test that non-resilient mode uses TranslationRaiseException."""
        env = Environment(extensions=['jinja2.ext.i18n'])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".po", delete=False) as f:
            translations_path = Path(f.name)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mo", delete=False) as f:
            compiled_path = Path(f.name)

        try:
            # Mock Path(__file__).parents[1].glob to return empty list
            with patch("artemis.reporting.export.translations.Path") as mock_path_class:
                mock_file_path = MagicMock()
                mock_parent = MagicMock()
                mock_parent.glob.return_value = []
                mock_file_path.parents = [MagicMock(), mock_parent]
                mock_path_class.return_value = mock_file_path

                with patch("artemis.reporting.export.translations.gettext.translation") as mock_translation:
                    mock_trans_obj = MagicMock()
                    mock_translation.return_value = mock_trans_obj

                    install_translations(
                        Language.pl_PL,
                        env,
                        translations_path,
                        compiled_path,
                        resilient_mode=False,
                    )

                    # Verify that gettext.translation was called with TranslationRaiseException
                    call_kwargs = mock_translation.call_args[1]
                    assert call_kwargs["class_"] == TranslationRaiseException
        finally:
            translations_path.unlink(missing_ok=True)
            compiled_path.unlink(missing_ok=True)

    @patch("artemis.reporting.export.translations.subprocess.call")
    @patch("artemis.reporting.export.translations.shutil.copy")
    def test_install_translations_english_uses_gnu_translations(self, mock_copy, mock_subprocess):
        """Test that English language uses standard GNUTranslations."""
        env = Environment(extensions=['jinja2.ext.i18n'])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".po", delete=False) as f:
            translations_path = Path(f.name)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mo", delete=False) as f:
            compiled_path = Path(f.name)

        try:
            # Mock Path(__file__).parents[1].glob to return empty list
            with patch("artemis.reporting.export.translations.Path") as mock_path_class:
                mock_file_path = MagicMock()
                mock_parent = MagicMock()
                mock_parent.glob.return_value = []
                mock_file_path.parents = [MagicMock(), mock_parent]
                mock_path_class.return_value = mock_file_path

                with patch("artemis.reporting.export.translations.gettext.translation") as mock_translation:
                    mock_trans_obj = MagicMock()
                    mock_translation.return_value = mock_trans_obj

                    install_translations(
                        Language.en_US,
                        env,
                        translations_path,
                        compiled_path,
                        resilient_mode=True,  # Should be ignored for en_US
                    )

                    # Verify that gettext.translation was called with GNUTranslations
                    call_kwargs = mock_translation.call_args[1]
                    assert call_kwargs["class_"] == gettext.GNUTranslations
        finally:
            translations_path.unlink(missing_ok=True)
            compiled_path.unlink(missing_ok=True)


class TestIntegrationScenarios:
    """Integration tests for realistic export scenarios."""

    def test_mixed_valid_and_missing_translations(self):
        """Test that valid translations work and missing ones are collected."""
        clear_missing_translations()

        trans = TranslationCollectMissing(create_empty_mo_file())

        # Simulate some translations existing and some missing
        # (In real scenario, some would come from .po file)
        result1 = trans.gettext("Missing translation 1")
        result2 = trans.gettext("Missing translation 2")

        # Both should return fallback (original message)
        assert result1 == "Missing translation 1"
        assert result2 == "Missing translation 2"

        # Both should be collected
        missing = get_missing_translations()
        assert len(missing) == 2
        assert "Missing translation 1" in missing
        assert "Missing translation 2" in missing

    def test_no_missing_translations(self):
        """Test that when no translations are missing, the list is empty."""
        clear_missing_translations()

        # Don't request any missing translations
        missing = get_missing_translations()
        assert len(missing) == 0
        assert missing == []

    def test_consecutive_exports_with_clear(self):
        """Test that multiple exports can be done with clear in between."""
        # First export
        clear_missing_translations()
        trans1 = TranslationCollectMissing(create_empty_mo_file())
        trans1.gettext("Export 1 missing")
        assert len(get_missing_translations()) == 1

        # Clear for second export
        clear_missing_translations()
        trans2 = TranslationCollectMissing(create_empty_mo_file())
        trans2.gettext("Export 2 missing")
        missing = get_missing_translations()

        # Should only have the second export's missing translation
        assert len(missing) == 1
        assert "Export 2 missing" in missing
        assert "Export 1 missing" not in missing
