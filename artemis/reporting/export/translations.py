import gettext
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from jinja2 import Environment

from artemis.reporting.base.language import Language
from artemis.reporting.exceptions import TranslationNotFoundException


class TranslationRaiseException(gettext.GNUTranslations):
    """This class is used instead of GNUTranslations and raises exception when a message is not found,
    so that we don't allow untranslated strings into the messages."""

    def gettext(self, message: str) -> str:
        message_translated = super().gettext(message)
        if message == message_translated:
            raise TranslationNotFoundException(f"Unable to translate '{message}'")
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
    translations_output_file_name: str,
    compiled_translations_output_file_name: str,
) -> None:
    """Collects all .pot files into one, compiles it and installs to Jinja2 environment. Saves the translations
    (both original and compiled) so that they can be used by downstream tools.

    We do this as late as possible in order to:
    - make it transparent for the user, so that they don't have to remember about a step,
    - allow the user to mount additional files as Docker volumes.
    """
    with open(translations_output_file_name, "w") as all_translations_file:
        for translation_path in Path(__file__).parents[1].glob(f"**/{language.value}/**/*.po"):
            with open(translation_path, "r") as translation_file:
                all_translations_file.write(translation_file.read() + "\n")

    os.makedirs(f"{language.value}/LC_MESSAGES", exist_ok=True)

    temporary_compiled_translations_output_file_name = f"{language.value}/LC_MESSAGES/messages.mo"

    subprocess.call(
        [
            "pybabel",
            "compile",
            "-f",
            "--input",
            translations_output_file_name,
            "--output",
            temporary_compiled_translations_output_file_name,
        ],
        stderr=subprocess.DEVNULL,  # suppress a misleading message where compiled translations will be saved
    )

    if language == Language.en_US:
        # For English we allow untranslated strings
        class_ = gettext.GNUTranslations
    else:
        class_ = TranslationRaiseException

    environment.install_gettext_translations(  # type: ignore
        gettext.translation(domain="messages", localedir=".", languages=[language.value], class_=class_)
    )

    shutil.copy(temporary_compiled_translations_output_file_name, compiled_translations_output_file_name)
