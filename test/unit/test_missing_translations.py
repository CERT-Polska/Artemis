import threading
import unittest

from artemis.reporting.base.missing_translations import (
    MissingTranslationCollector,
    collecting_missing_translations,
    current_missing_translations,
)
from artemis.reporting.exceptions import TranslationNotFoundException


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
