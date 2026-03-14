from typing import Set

_missing_translations: Set[str] = set()


class TranslationNotFoundException(Exception):
    def __init__(self, message: str):
        self._message = message

    def __str__(self) -> str:
        return self._message


def record_missing_translation(message: str) -> None:
    _missing_translations.add(message)


def get_missing_translations() -> Set[str]:
    return _missing_translations


def clear_missing_translations() -> None:
    _missing_translations.clear()
