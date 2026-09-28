import logging
from contextvars import ContextVar
from typing import Sequence

_current_root_uids: ContextVar[tuple[str, ...]] = ContextVar("artemis_current_root_uids", default=())


class RunContextFilter(logging.Filter):
    """Annotate each log record with the analysis(es) currently being processed."""

    def filter(self, record: logging.LogRecord) -> bool:
        root_uids = _current_root_uids.get()
        record.analysis_id = ",".join(root_uids) if root_uids else "-"
        return True


def set_current_root_uids(root_uids: Sequence[str]) -> None:
    _current_root_uids.set(tuple(root_uids))


def reset_current_root_uids() -> None:
    _current_root_uids.set(())
