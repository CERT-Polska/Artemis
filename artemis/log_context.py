import logging
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Generator

_current_run_hash: ContextVar[str] = ContextVar("artemis_current_run_hash", default="-")


class RunContextFilter(logging.Filter):
    """Annotate each log record with a short random hash identifying the current processing run."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_hash = _current_run_hash.get()
        return True


@contextmanager
def run_hash_scope() -> Generator[None, None, None]:
    _current_run_hash.set("#" + secrets.token_hex(4))
    try:
        yield
    finally:
        _current_run_hash.set("-")
