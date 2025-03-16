import gettext
import os
import shutil
import subprocess
import threading
import inspect
from pathlib import Path
from typing import Set, Dict, List, Tuple

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
    # Changed from Set[str] to Dict[str, List[Tuple[str, int]]] to store context information
    missing_translations: Dict[str, List[Tuple[str, int]]] = {}
    # Lock to protect access to missing_translations
    _lock = threading.Lock()

    @classmethod
    def _add_missing_translation(cls, message: str, filename=None, lineno=None) -> None:
        """Add a missing translation with context information from the stack."""
        if filename is None or lineno is None:
            # Get the current stack
            stack = inspect.stack()
            
            # Find the relevant frame (skip translation machinery frames)
            # We need to skip frames related to the translation machinery itself
            frame_info = None
            for frame in stack[1:]:  # Skip the current frame
                if not (frame.filename.endswith('translations.py') or 
                        'gettext' in frame.filename or
                        'jinja2' in frame.filename):
                    frame_info = frame
                    break
            
            if frame_info:
                filename = frame_info.filename
                lineno = frame_info.lineno
            else:
                # If we couldn't find a relevant frame, use generic info
                filename = "unknown"
                lineno = 0
        
        with cls._lock:
            if message not in cls.missing_translations:
                cls.missing_translations[message] = []
            
            # Add this location if it's not already recorded
            location = (filename, lineno)
            if location not in cls.missing_translations[message]:
                cls.missing_translations[message].append(location)

    @classmethod
    def _escape_po_string(cls, s: str) -> str:
        """Escape a string for use in a PO file."""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

    @classmethod
    def _get_relative_path(cls, path: str) -> str:
        """Convert an absolute path to a relative path from the project root."""
        try:
            # Try to get the project root (this is a simple heuristic)
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            if path.startswith(project_root):
                return os.path.relpath(path, project_root)
            return path
        except Exception:
            return path

    class _TranslationCollector(gettext.GNUTranslations):
        def gettext(self, message: str) -> str:
            # Record missing translation with context
            TranslationCollectMissingException._add_missing_translation(message)
            # Return original message
            return message

        def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
            # Record missing translations with context
            TranslationCollectMissingException._add_missing_translation(msgid1)
            TranslationCollectMissingException._add_missing_translation(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

        def pgettext(self, context: str, message: str) -> str:
            # Record missing translation with context
            TranslationCollectMissingException._add_missing_translation(message)
            # Return original message
            return message

        def npgettext(self, context: str, msgid1: str, msgid2: str, n: int) -> str:
            # Record missing translations with context
            TranslationCollectMissingException._add_missing_translation(msgid1)
            TranslationCollectMissingException._add_missing_translation(msgid2)
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
            # Record missing translation with context
            TranslationCollectMissingException._add_missing_translation(message)
            # Return original message
            return message

    def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
        try:
            return super().ngettext(msgid1, msgid2, n)
        except Exception:
            # Record missing translations with context
            TranslationCollectMissingException._add_missing_translation(msgid1)
            TranslationCollectMissingException._add_missing_translation(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

    def pgettext(self, context: str, message: str) -> str:
        try:
            return super().pgettext(context, message)
        except Exception:
            # Record missing translation with context
            TranslationCollectMissingException._add_missing_translation(message)
            # Return original message
            return message

    def npgettext(self, context: str, msgid1: str, msgid2: str, n: int) -> str:
        try:
            return super().npgettext(context, msgid1, msgid2, n)
        except Exception:
            # Record missing translations with context
            TranslationCollectMissingException._add_missing_translation(msgid1)
            TranslationCollectMissingException._add_missing_translation(msgid2)
            # Return original message based on n
            return msgid1 if n == 1 else msgid2

    @classmethod
    def get_missing_translations(cls) -> Set[str]:
        """Returns the set of missing translations."""
        with cls._lock:
            # Return a copy of the keys to avoid concurrent modification issues
            return set(cls.missing_translations.keys())

    @classmethod
    def clear_missing_translations(cls) -> None:
        """Clears the dictionary of missing translations."""
        with cls._lock:
            cls.missing_translations = {}

    @classmethod
    def save_missing_translations_to_file(cls, file_path: Path) -> None:
        """Saves the missing translations to a file in .po format with context information."""
        # Get a thread-safe copy of the missing translations
        with cls._lock:
            translations_to_save = dict(cls.missing_translations)
        
        with open(file_path, "w") as f:
            for message, locations in translations_to_save.items():
                # Write source references
                for filename, lineno in locations:
                    rel_filename = cls._get_relative_path(filename)
                    f.write(f"#: {rel_filename}:{lineno}\n")
                
                # Write the message with proper escaping
                escaped_message = cls._escape_po_string(message)
                f.write(f'msgid "{escaped_message}"\nmsgstr ""\n\n')


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
