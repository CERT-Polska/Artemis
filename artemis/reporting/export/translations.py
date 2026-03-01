import gettext
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, List, Set

from jinja2 import Environment

from artemis.reporting.base.language import Language
from artemis.reporting.exceptions import TranslationNotFoundException


# Global set to collect missing translations
_missing_translations: Set[str] = set()


def get_missing_translations() -> List[str]:
    """Return the list of missing translations collected during export."""
    return sorted(list(_missing_translations))


def clear_missing_translations() -> None:
    """Clear the collected missing translations."""
    global _missing_translations
    _missing_translations = set()


class TranslationRaiseException(gettext.GNUTranslations):
    """This class is used instead of GNUTranslations and raises exception when a message is not found,
    so that we don't allow untranslated strings into the messages."""

    class _TranslationAlwaysRaiseException(gettext.GNUTranslations):
        def gettext(self, message: str) -> str:
            raise TranslationNotFoundException(f"Unable to translate '{message}'")

        def ngettext(self, *args: Any) -> Any:
            raise NotImplementedError()

        def pgettext(self, *args: Any) -> Any:
            raise NotImplementedError()

        def npgettext(self, *args: Any) -> Any:
            raise NotImplementedError()

    def __init__(self, fp=None):  # type: ignore
        super().__init__(fp)

        self.add_fallback(self._TranslationAlwaysRaiseException())

    def gettext(self, message: str) -> str:
        message_translated = super().gettext(message)
        return message_translated

    def ngettext(self, *args: Any) -> Any:
        raise NotImplementedError()

    def pgettext(self, *args: Any) -> Any:
        raise NotImplementedError()

    def npgettext(self, *args: Any) -> Any:
        raise NotImplementedError()


class TranslationCollectMissing(gettext.GNUTranslations):
    """This class collects missing translations instead of raising exceptions immediately."""

    class _TranslationCollectMissingFallback:
        """Fallback that collects missing translations instead of raising."""

        def gettext(self, message: str) -> str:
            global _missing_translations
            _missing_translations.add(message)
            return message  # Return the original message as fallback

        def ngettext(self, *args: Any) -> Any:
            raise NotImplementedError()

        def pgettext(self, *args: Any) -> Any:
            raise NotImplementedError()

        def npgettext(self, *args: Any) -> Any:
            raise NotImplementedError()

    def __init__(self, fp=None):  # type: ignore
        super().__init__(fp)
        self.add_fallback(self._TranslationCollectMissingFallback())

    def gettext(self, message: str) -> str:
        # First try to get from catalog
        message_translated = super().gettext(message)
        # If it's the same as original, it means it wasn't translated
        # But super().gettext() would have triggered the fallback chain
        return message_translated

    def ngettext(self, *args: Any) -> Any:
        raise NotImplementedError()

    def pgettext(self, *args: Any) -> Any:
        raise NotImplementedError()

    def npgettext(self, *args: Any) -> Any:
        raise NotImplementedError()


def install_translations(
    language: Language,
    environment: Environment,
    save_translations_to: Path,
    save_compiled_translations_to: Path,
    resilient_mode: bool = True,
) -> None:
    """Collects all .pot files into one, compiles it and installs to Jinja2 environment. Saves the translations
    (both original and compiled) so that they can be used by downstream tools.

    We do this as late as possible in order to allow the user to mount additional files as Docker volumes.

    Args:
        language: The language to use for translations
        environment: Jinja2 environment to install translations to
        save_translations_to: Path to save the collected translations
        save_compiled_translations_to: Path to save the compiled translations
        resilient_mode: If True, collect missing translations instead of raising exceptions (default: True)
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
        # For English we allow untranslated strings
        class_ = gettext.GNUTranslations
    elif resilient_mode:
        # Collect missing translations instead of raising exceptions
        class_ = TranslationCollectMissing
    else:
        # Raise exceptions on missing translations (old behavior)
        class_ = TranslationRaiseException

    environment.install_gettext_translations(  # type: ignore
        gettext.translation(domain="messages", localedir=".", languages=[language.value], class_=class_)
    )

    shutil.copy(pybabel_compiled_path, save_compiled_translations_to)
