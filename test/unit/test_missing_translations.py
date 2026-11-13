import io
import struct
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Generator
from unittest.mock import patch

from jinja2 import BaseLoader, Environment, StrictUndefined, select_autoescape

from artemis.reporting.base.language import Language
from artemis.reporting.base.missing_translations import (
    MissingTranslationCollector,
    collecting_missing_translations,
    current_missing_translations,
)
from artemis.reporting.exceptions import TranslationNotFoundException
from artemis.reporting.export.export_data import (
    ExportData,
    SingleTopLevelTargetExportData,
)
from artemis.reporting.export.main import export
from artemis.reporting.export.translations import TranslationRaiseException


class MissingTranslationCollectorTest(unittest.TestCase):
    def test_empty_collector_does_not_raise(self) -> None:
        MissingTranslationCollector().raise_if_any()

    def test_duplicate_messages_are_listed_once(self) -> None:
        collector = MissingTranslationCollector()
        collector.add("Unable to translate 'same'")
        collector.add("Unable to translate 'same'")

        with self.assertRaises(TranslationNotFoundException) as caught:
            collector.raise_if_any()

        self.assertEqual(str(caught.exception), "Found 1 missing translation(s):\n- Unable to translate 'same'")

    def test_lists_every_message_in_sorted_order(self) -> None:
        collector = MissingTranslationCollector()
        collector.add("Unable to translate 'beta'")
        collector.add("Unable to translate 'alpha'")

        with self.assertRaises(TranslationNotFoundException) as caught:
            collector.raise_if_any()

        self.assertEqual(
            str(caught.exception),
            "Found 2 missing translation(s):\n" "- Unable to translate 'alpha'\n" "- Unable to translate 'beta'",
        )


class CollectingMissingTranslationsTest(unittest.TestCase):
    def test_collector_is_active_only_inside_the_block(self) -> None:
        self.assertIsNone(current_missing_translations())

        with collecting_missing_translations() as collector:
            self.assertIs(current_missing_translations(), collector)
            collector.add("inside")

        self.assertIsNone(current_missing_translations())
        with self.assertRaises(TranslationNotFoundException):
            collector.raise_if_any()

    def test_nested_block_restores_the_outer_collector(self) -> None:
        with collecting_missing_translations() as outer:
            outer.add("outer")
            with collecting_missing_translations() as inner:
                inner.add("inner")
                self.assertIs(current_missing_translations(), inner)
            self.assertIs(current_missing_translations(), outer)

        with self.assertRaises(TranslationNotFoundException) as caught:
            outer.raise_if_any()
        self.assertIn("outer", str(caught.exception))
        self.assertNotIn("inner", str(caught.exception))

    def test_threads_keep_separate_collectors(self) -> None:
        barrier = threading.Barrier(2)
        errors: dict[str, BaseException] = {}

        def record(name: str, message: str) -> None:
            with collecting_missing_translations() as collector:
                barrier.wait()
                collector.add(message)
                barrier.wait()
                try:
                    collector.raise_if_any()
                except TranslationNotFoundException as error:
                    errors[name] = error

        threads = [
            threading.Thread(target=record, args=("one", "missing-one")),
            threading.Thread(target=record, args=("two", "missing-two")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertIn("missing-one", str(errors["one"]))
        self.assertNotIn("missing-two", str(errors["one"]))
        self.assertIn("missing-two", str(errors["two"]))
        self.assertNotIn("missing-one", str(errors["two"]))


def _catalog(*pairs: tuple[str, str]) -> TranslationRaiseException:
    # The empty msgid is the catalog header. GNUTranslations reads the charset from it.
    entries = [("", "Content-Type: text/plain; charset=UTF-8\n"), *pairs]
    encoded = [(msgid.encode(), msgstr.encode()) for msgid, msgstr in entries]
    count = len(encoded)
    key_table = 28
    value_table = key_table + count * 8
    cursor = value_table + count * 8

    key_index = []
    value_index = []
    blobs = []
    for msgid, msgstr in encoded:
        key_index.append((len(msgid), cursor))
        blobs.append(msgid + b"\x00")
        cursor += len(msgid) + 1
        value_index.append((len(msgstr), cursor))
        blobs.append(msgstr + b"\x00")
        cursor += len(msgstr) + 1

    output = struct.pack("<7I", 0x950412DE, 0, count, key_table, value_table, 0, 0)
    for length, offset in key_index + value_index:
        output += struct.pack("<II", length, offset)
    return TranslationRaiseException(io.BytesIO(output + b"".join(blobs)))  # type: ignore[no-untyped-call]


def _environment(translations: TranslationRaiseException) -> Environment:
    environment = Environment(
        loader=BaseLoader(),
        extensions=["jinja2.ext.i18n"],
        undefined=StrictUndefined,
        autoescape=select_autoescape(default=True),
    )
    environment.install_gettext_translations(translations)  # type: ignore
    return environment


_TEMPLATE = (
    "{% trans %}Already translated.{% endtrans %}\n"
    "{% trans count=5 %}One present.{% pluralize %}Many present.{% endtrans %}\n"
    "{% trans %}Missing singular.{% endtrans %}\n"
    "{% trans count=2 %}One missing item.{% pluralize %}Many missing items.{% endtrans %}"
)


class MissingGettextTest(unittest.TestCase):
    def _translations(self) -> TranslationRaiseException:
        return _catalog(
            ("Already translated.", "Już przetłumaczone."),
            ("One present.\x00Many present.", "Jedna.\x00Wiele."),
        )

    def test_missing_singular_and_plural_are_recorded_and_rendered_in_english(self) -> None:
        translations = self._translations()
        template = _environment(translations).from_string(_TEMPLATE)

        with collecting_missing_translations() as collector:
            rendered = template.render()

        self.assertEqual(
            rendered,
            "Już przetłumaczone.\nWiele.\nMissing singular.\nMany missing items.",
        )
        with self.assertRaises(TranslationNotFoundException) as caught:
            collector.raise_if_any()
        self.assertEqual(
            str(caught.exception),
            "Found 2 missing translation(s):\n"
            "- Unable to translate 'Many missing items.'\n"
            "- Unable to translate 'Missing singular.'",
        )

        with collecting_missing_translations() as collector:
            self.assertEqual(translations.ngettext("One missing item.", "Many missing items.", 1), "One missing item.")
        with self.assertRaises(TranslationNotFoundException) as caught:
            collector.raise_if_any()
        self.assertEqual(
            str(caught.exception),
            "Found 1 missing translation(s):\n- Unable to translate 'One missing item.'",
        )

    def test_without_collector_the_first_missing_string_raises(self) -> None:
        translations = self._translations()
        template = _environment(translations).from_string(_TEMPLATE)

        with self.assertRaises(TranslationNotFoundException) as caught:
            template.render()
        self.assertEqual(str(caught.exception), "Unable to translate 'Missing singular.'")

        with self.assertRaises(TranslationNotFoundException) as caught:
            translations.ngettext("One missing item.", "Many missing items.", 2)
        self.assertEqual(str(caught.exception), "Unable to translate 'Many missing items.'")


_EXPORT_TEMPLATE = (
    "{% trans %}Already translated.{% endtrans %}\n"
    "{% trans %}Missing singular.{% endtrans %}\n"
    "{% trans count=2 %}One missing item.{% pluralize %}Many missing items.{% endtrans %}"
)


def _export_data() -> ExportData:
    message = SingleTopLevelTargetExportData(
        custom_template_arguments={},
        top_level_target_is_domain=True,
        top_level_target="example.com",
        contains_type=[],
        reports=[],
        assets=[],
    )
    return ExportData(
        timestamp="2026-01-01T00:00:00",
        tag=None,
        language="pl_PL",
        scanned_top_level_targets=["example.com"],
        scanned_targets=["example.com"],
        ips={},
        messages={"example.com": message},
        alerts=[],
        hosts_with_waf_detected=[],
    )


@contextmanager
def _patched_export(translations: TranslationRaiseException, output_root: Path) -> Generator[None, None, None]:
    def install(language: Language, environment: Environment, save_to: Path, compiled_to: Path) -> None:
        environment.install_gettext_translations(translations)  # type: ignore[attr-defined]

    with (
        patch("artemis.reporting.export.main.OUTPUT_LOCATION", output_root),
        patch("artemis.reporting.export.main.load_blocklist", return_value=[]),
        patch("artemis.reporting.export.main.DB"),
        patch("artemis.reporting.export.main.DataLoader"),
        patch("artemis.reporting.export.main.build_export_data", return_value=_export_data()),
        patch("artemis.reporting.export.main.install_translations", install),
        patch("artemis.reporting.export.main.build_message_template", return_value=_EXPORT_TEMPLATE),
    ):
        yield


class ExportMissingTranslationsTest(unittest.TestCase):
    def test_export_fails_once_with_every_missing_translation(self) -> None:
        translations = _catalog(("Already translated.", "Już przetłumaczone."))
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)
            with _patched_export(translations, output_root):
                stdout = StringIO()
                with redirect_stdout(stdout):
                    with self.assertRaises(TranslationNotFoundException) as caught:
                        export(Language.pl_PL, silent=True, skip_hooks=True)  # type: ignore[attr-defined]

            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                str(caught.exception),
                "Found 2 missing translation(s):\n"
                "- Unable to translate 'Many missing items.'\n"
                "- Unable to translate 'Missing singular.'",
            )
            self.assertEqual(list(output_root.rglob("output.json")), [])
            self.assertEqual(list(output_root.rglob("stats.txt")), [])

    def test_export_with_a_complete_catalog_writes_the_output(self) -> None:
        translations = _catalog(
            ("Already translated.", "Już przetłumaczone."),
            ("Missing singular.", "Brakuje liczby pojedynczej."),
            ("One missing item.\x00Many missing items.", "Jedna.\x00Wiele."),
        )
        with tempfile.TemporaryDirectory() as tmp:
            output_root = Path(tmp)
            with _patched_export(translations, output_root):
                stdout = StringIO()
                with redirect_stdout(stdout):
                    output_dir = export(Language.pl_PL, silent=True, skip_hooks=True)  # type: ignore[attr-defined]

            self.assertIn(str(output_dir), stdout.getvalue())
            self.assertTrue((output_dir / "advanced" / "output.json").is_file())
            self.assertTrue((output_dir / "stats.txt").is_file())
