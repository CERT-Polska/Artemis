from contextlib import contextmanager
from contextvars import ContextVar
from typing import Generator, Optional

from artemis.reporting.exceptions import TranslationNotFoundException

_current_collector: ContextVar[Optional["MissingTranslationCollector"]] = ContextVar(
    "artemis_missing_translation_collector", default=None
)


class MissingTranslationCollector:
    """Collects missing translations so that all of them can be reported at once, not only the first one."""

    def __init__(self) -> None:
        self._messages: set[str] = set()

    def add(self, message: str) -> None:
        self._messages.add(message)

    def raise_if_any(self) -> None:
        if self._messages:
            listed = "\n".join(f"- {message}" for message in sorted(self._messages))
            raise TranslationNotFoundException(f"Found {len(self._messages)} missing translation(s):\n{listed}")


def current_missing_translations() -> Optional[MissingTranslationCollector]:
    """Returns the collector for the current context, or None if missing translations aren't being collected."""
    return _current_collector.get()


@contextmanager
def collecting_missing_translations() -> Generator[MissingTranslationCollector, None, None]:
    collector = MissingTranslationCollector()
    # Using reset() instead of set(None) so that a nested block restores the outer collector.
    token = _current_collector.set(collector)
    try:
        yield collector
    finally:
        _current_collector.reset(token)
