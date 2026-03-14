import unittest

from artemis.reporting.exceptions import (
    clear_missing_translations,
    get_missing_translations,
    record_missing_translation,
)
from artemis.reporting.export.translations import TranslationRaiseException


class MissingTranslationsCollectorTest(unittest.TestCase):
    def setUp(self) -> None:
        clear_missing_translations()

    def tearDown(self) -> None:
        clear_missing_translations()

    def test_no_missing_translations_initially(self) -> None:
        self.assertEqual(len(get_missing_translations()), 0)

    def test_record_single_missing_translation(self) -> None:
        record_missing_translation("Unable to translate 'some message'")
        missing = get_missing_translations()
        self.assertEqual(len(missing), 1)
        self.assertIn("Unable to translate 'some message'", missing)

    def test_record_multiple_missing_translations(self) -> None:
        record_missing_translation("Unable to translate 'message one'")
        record_missing_translation("Unable to translate 'message two'")
        record_missing_translation("Unable to translate 'message three'")
        missing = get_missing_translations()
        self.assertEqual(len(missing), 3)

    def test_duplicates_are_deduplicated(self) -> None:
        record_missing_translation("Unable to translate 'same message'")
        record_missing_translation("Unable to translate 'same message'")
        missing = get_missing_translations()
        self.assertEqual(len(missing), 1)

    def test_clear_removes_all(self) -> None:
        record_missing_translation("Unable to translate 'message'")
        self.assertEqual(len(get_missing_translations()), 1)
        clear_missing_translations()
        self.assertEqual(len(get_missing_translations()), 0)


class TranslationFallbackTest(unittest.TestCase):
    def setUp(self) -> None:
        clear_missing_translations()

    def tearDown(self) -> None:
        clear_missing_translations()

    def test_missing_gettext_returns_original_and_records(self) -> None:
        fallback = TranslationRaiseException._TranslationAlwaysRaiseException()
        result = fallback.gettext("untranslated string")
        self.assertEqual(result, "untranslated string")
        missing = get_missing_translations()
        self.assertEqual(len(missing), 1)
        self.assertIn("Unable to translate 'untranslated string'", missing)

    def test_multiple_missing_gettext_all_recorded(self) -> None:
        fallback = TranslationRaiseException._TranslationAlwaysRaiseException()
        fallback.gettext("first")
        fallback.gettext("second")
        fallback.gettext("third")
        self.assertEqual(len(get_missing_translations()), 3)
