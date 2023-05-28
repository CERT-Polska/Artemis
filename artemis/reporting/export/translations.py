import gettext
import os
import shutil
import subprocess
from pathlib import Path

from jinja2 import Environment

from artemis.reporting.base.language import Language


def install_translations(
    translations_file_name: str, compiled_translations_file_name: str, language: Language, environment: Environment
) -> None:
    """Collects all .pot files into one, compiles it and installs to Jinja2 environment.

    We do this as late as possible in order to:
    - make it transparent for the user, so that they don't have to remember about a step,
    - allow the user to mount additional files as Docker volumes.
    """
    with open(translations_file_name, "w") as all_translations_file:
        for translation_path in Path(__file__).parents[1].glob(f"**/{language.value}/LC_MESSAGES/messages.po"):
            with open(translation_path, "r") as translation_file:
                all_translations_file.write(translation_file.read() + "\n")

    os.makedirs(f"{language.value}/LC_MESSAGES", exist_ok=True)

    temporary_compiled_translations_file_name = f"{language.value}/LC_MESSAGES/messages.mo"

    subprocess.call(
        [
            "pybabel",
            "compile",
            "-f",
            "--input",
            translations_file_name,
            "--output",
            temporary_compiled_translations_file_name,
        ],
        stderr=subprocess.DEVNULL,  # suppress a misleading message where compiled translations will be saved
    )

    environment.install_gettext_translations(  # type: ignore
        gettext.translation(domain="messages", localedir=".", languages=[language.value])
    )

    shutil.copy(temporary_compiled_translations_file_name, compiled_translations_file_name)
