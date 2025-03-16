import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jinja2 import BaseLoader, Environment, StrictUndefined

from artemis.reporting.base.language import Language
from artemis.reporting.exceptions import TranslationNotFoundException
from artemis.reporting.export.translations import (
    TranslationCollectMissingException,
    TranslationRaiseException,
    install_translations,
)


class TestExportTranslations(unittest.TestCase):
    def setUp(self):
        self.environment = Environment(
            loader=BaseLoader(),
            extensions=["jinja2.ext.i18n"],
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.translations_path = self.temp_path / "translations.po"
        self.compiled_translations_path = self.temp_path / "compiled_translations.mo"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_strict_mode_raises_exception(self):
        """Test that strict mode raises an exception for missing translations."""
        # Set up a non-English language
        language = Language.pl_PL

        # Install translations in strict mode (explicitly set strict_mode=True)
        install_translations(
            language,
            self.environment,
            self.translations_path,
            self.compiled_translations_path,
            strict_mode=True,  # Need to explicitly set strict mode now
        )

        # Attempt to translate a string that doesn't exist in translations
        with self.assertRaises(TranslationNotFoundException):
            self.environment.gettext("This string doesn't exist in translations")

    def test_default_mode_returns_original_text(self):
        """Test that default (lenient) mode returns the original text for missing translations."""
        # Set up a non-English language
        language = Language.pl_PL

        # Clear any previous missing translations
        TranslationCollectMissingException.clear_missing_translations()

        # Install translations with default settings (lenient mode is now default)
        install_translations(
            language,
            self.environment,
            self.translations_path,
            self.compiled_translations_path,
            # strict_mode is False by default now
        )

        # Translate a string that doesn't exist in translations
        test_string = "This string doesn't exist in translations"
        result = self.environment.gettext(test_string)

        # Check that the original string is returned
        self.assertEqual(result, test_string)

        # Check that the missing translation was collected
        missing_translations = TranslationCollectMissingException.get_missing_translations()
        self.assertIn(test_string, missing_translations)

    def test_save_missing_translations(self):
        """Test that missing translations are saved to a file."""
        # Set up a non-English language
        language = Language.pl_PL

        # Clear any previous missing translations
        TranslationCollectMissingException.clear_missing_translations()

        # Install translations with default settings (lenient mode)
        install_translations(
            language,
            self.environment,
            self.translations_path,
            self.compiled_translations_path,
            # strict_mode is False by default now
        )

        # Translate a few strings that don't exist in translations
        test_strings = [
            "This is the first missing string",
            "This is the second missing string",
            "This is the third missing string",
        ]

        for test_string in test_strings:
            self.environment.gettext(test_string)

        # Save missing translations to a file
        missing_translations_path = self.temp_path / "missing_translations.po"
        TranslationCollectMissingException.save_missing_translations_to_file(missing_translations_path)

        # Check that the file was created
        self.assertTrue(missing_translations_path.exists())

        # Check the content of the file
        with open(missing_translations_path, "r") as f:
            content = f.read()

        for test_string in test_strings:
            self.assertIn(f'msgid "{test_string}"', content)
            self.assertIn('msgstr ""', content)


if __name__ == "__main__":
    unittest.main()
