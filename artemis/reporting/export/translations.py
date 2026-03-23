import gettext
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from jinja2 import Environment

from artemis.reporting.base.language import Language
from artemis.reporting.exceptions import TranslationNotFoundException


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


def install_translations(
    language: Language,
    environment: Environment,
    save_translations_to: Path,
    save_compiled_translations_to: Path,
) -> None:
    """Collects all .pot files into one, compiles it and installs to Jinja2 environment. Saves the translations
    (both original and compiled) so that they can be used by downstream tools.

    We do this as late as possible in order to allow the user to mount additional files as Docker volumes.
    """
    with open(save_translations_to, "w") as all_translations_file:
        for translation_path in Path(__file__).parents[1].glob(f"**/{language.value}/**/*.po"):
            with open(translation_path, "r") as translation_file:
                all_translations_file.write(translation_file.read() + "\n")

    if language == Language.en_US:  # type: ignore
        # For English we allow untranslated strings
        class_ = gettext.GNUTranslations
    else:
        class_ = TranslationRaiseException

    # Use a per-call temporary directory for the intermediate .mo file so that
    # concurrent callers (the report-generation thread and the API thread) do
    # not clobber each other's compiled output.  Previously, a shared relative
    # path ``{language}/LC_MESSAGES/messages.mo`` was used, which caused a race
    # condition when both threads called install_translations simultaneously.
    with tempfile.TemporaryDirectory() as tmp_localedir:
        lc_messages_dir = os.path.join(tmp_localedir, language.value, "LC_MESSAGES")
        os.makedirs(lc_messages_dir)
        pybabel_compiled_path = os.path.join(lc_messages_dir, "messages.mo")

        returncode = subprocess.call(
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
        if returncode != 0:
            raise RuntimeError(f"pybabel compile failed with exit code {returncode} for input {save_translations_to}")

        environment.install_gettext_translations(  # type: ignore
            gettext.translation(domain="messages", localedir=tmp_localedir, languages=[language.value], class_=class_)
        )

        shutil.copy(pybabel_compiled_path, save_compiled_translations_to)
