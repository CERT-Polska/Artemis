import gettext
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Set

from jinja2 import Environment

from artemis.reporting.base.language import Language
from artemis.reporting.exceptions import TranslationNotFoundException


class TranslationRaiseException(gettext.GNUTranslations):
    """This class is used instead of GNUTranslations and raises exception when a message is not found,
    so that we don't allow untranslated strings into the messages."""

    class _TranslationAlwaysRaiseException(gettext.GNUTranslations):
        def gettext(self, message: str) -> str:
            raise TranslationNotFoundException(f"Unable to translate '{message}'")

        def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
            raise TranslationNotFoundException(f"Unable to translate '{msgid1}' or '{msgid2}'")

        def pgettext(self, context: str, message: str) -> str:
            raise TranslationNotFoundException(f"Unable to translate '{message}' in context '{context}'")

        def npgettext(self, context: str, msgid1: str, msgid2: str, n: int) -> str:
            raise TranslationNotFoundException(f"Unable to translate '{msgid1}' or '{msgid2}' in context '{context}'")

    def __init__(self, fp=None):  # type: ignore
        super().__init__(fp)

        self.add_fallback(self._TranslationAlwaysRaiseException())

    def gettext(self, message: str) -> str:
        message_translated = super().gettext(message)
        return message_translated

    def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
        try:
            return super().ngettext(msgid1, msgid2, n)
        except AttributeError:
            raise TranslationNotFoundException(f"Unable to translate '{msgid1}' or '{msgid2}'")

    def pgettext(self, context: str, message: str) -> str:
        try:
            return super().pgettext(context, message)
        except AttributeError:
            raise TranslationNotFoundException(f"Unable to translate '{message}' in context '{context}'")

    def npgettext(self, context: str, msgid1: str, msgid2: str, n: int) -> str:
        try:
            return super().npgettext(context, msgid1, msgid2, n)
        except AttributeError:
            raise TranslationNotFoundException(f"Unable to translate '{msgid1}' or '{msgid2}' in context '{context}'")


class TranslationCollectMissingException(gettext.GNUTranslations):
    """This class is used to collect missing translations instead of raising exceptions.
    It keeps track of all missing translations and returns the original message."""

    # Class variable to collect missing translations across all instances
    missing_translations: Set[str] = set()
    # Lock to protect access to missing_translations
    _lock = threading.Lock()

    class _TranslationCollector(gettext.GNUTranslations):
        def gettext(self, message: str) -> str:
            # Record missing translation
            with TranslationCollectMissingException._lock:
                TranslationCollectMissingException.missing_translations.add(message)
            # Return original message
            return message

        def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
            # Record missing translations
            with TranslationCollectMissingException._lock:
                TranslationCollectMissingException.missing_translations.add(msgid1)
                TranslationCollectMissingException.missing_translations.add(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

        def pgettext(self, context: str, message: str) -> str:
            # Record missing translation with context
            with TranslationCollectMissingException._lock:
                TranslationCollectMissingException.missing_translations.add(message)
            # Return original message
            return message

        def npgettext(self, context: str, msgid1: str, msgid2: str, n: int) -> str:
            # Record missing translations with context
            with TranslationCollectMissingException._lock:
                TranslationCollectMissingException.missing_translations.add(msgid1)
                TranslationCollectMissingException.missing_translations.add(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

    def __init__(self, fp=None):  # type: ignore
        super().__init__(fp)
        self.add_fallback(self._TranslationCollector())

    def gettext(self, message: str) -> str:
        try:
            message_translated = super().gettext(message)
            return message_translated
        except Exception:
            # Record missing translation
            with self._lock:
                TranslationCollectMissingException.missing_translations.add(message)
            # Return original message
            return message

    def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
        try:
            return super().ngettext(msgid1, msgid2, n)
        except Exception:
            # Record missing translations
            with self._lock:
                TranslationCollectMissingException.missing_translations.add(msgid1)
                TranslationCollectMissingException.missing_translations.add(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

    def pgettext(self, context: str, message: str) -> str:
        try:
            return super().pgettext(context, message)
        except Exception:
            # Record missing translation with context
            with self._lock:
                TranslationCollectMissingException.missing_translations.add(message)
            # Return original message
            return message

    def npgettext(self, context: str, msgid1: str, msgid2: str, n: int) -> str:
        try:
            return super().npgettext(context, msgid1, msgid2, n)
        except Exception:
            # Record missing translations with context
            with self._lock:
                TranslationCollectMissingException.missing_translations.add(msgid1)
                TranslationCollectMissingException.missing_translations.add(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

    @classmethod
    def get_missing_translations(cls) -> Set[str]:
        """Returns the set of missing translations."""
        with cls._lock:
            # Return a copy of the set to avoid concurrent modification issues
            return set(cls.missing_translations)

    @classmethod
    def clear_missing_translations(cls) -> None:
        """Clears the set of missing translations."""
        with cls._lock:
            cls.missing_translations = set()

    @classmethod
    def save_missing_translations_to_file(cls, file_path: Path) -> None:
        """Saves the missing translations to a file in .po format."""
        # Get a thread-safe copy of the missing translations
        with cls._lock:
            translations_to_save = set(cls.missing_translations)
            
        with open(file_path, "w") as f:
            for message in translations_to_save:
                f.write(f'msgid "{message}"\nmsgstr ""\n\n')


def install_translations(
    language: Language,
    environment: Environment,
    save_translations_to: Path,
    save_compiled_translations_to: Path,
    strict_mode: bool = False,
) -> None:
    """Collects all .pot files into one, compiles it and installs to Jinja2 environment. Saves the translations
    (both original and compiled) so that they can be used by downstream tools.

    We do this as late as possible in order to allow the user to mount additional files as Docker volumes.

    Args:
        language: The language to install translations for
        environment: The Jinja2 environment
        save_translations_to: Path to save the translation file
        save_compiled_translations_to: Path to save the compiled translation file
        strict_mode: If True, raises an exception when a translation is missing; if False (default), returns the original text
    """
    with open(save_translations_to, "w") as all_translations_file:
        for translation_path in Path(__file__).parents[1].glob(f"**/{language.value}/**/*.po"):
            with open(translation_path, "r") as translation_file:
                all_translations_file.write(translation_file.read() + "\n")

    os.makedirs(f"{language.value}/LC_MESSAGES", exist_ok=True)

    pybabel_compiled_path = f"{language.value}/LC_MESSAGES/messages.mo"

    subprocess.call(
        [
            "pybabel",
            "compile",
            "-f",
            "--input",
            save_translations_to,
            "--output",
            pybabel_compiled_path,
        ],
        stderr=subprocess.DEVNULL,  # suppress a misleading message where compiled translations will be saved
    )

    if language == Language.en_US:  # type: ignore
        # For English we always allow untranslated strings
        class_ = gettext.GNUTranslations
    else:
        # For other languages, use strict or non-strict mode based on the parameter
        if strict_mode:
            class_ = TranslationRaiseException
        else:
            # Clear any previously collected missing translations
            TranslationCollectMissingException.clear_missing_translations()
            class_ = TranslationCollectMissingException

    environment.install_gettext_translations(  # type: ignore
        gettext.translation(domain="messages", localedir=".", languages=[language.value], class_=class_)
    )

    shutil.copy(pybabel_compiled_path, save_compiled_translations_to)
