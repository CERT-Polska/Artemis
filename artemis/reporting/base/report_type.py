import functools
from typing import List

from .reporters import get_all_reporters


class ReportType(str):
    @functools.lru_cache(maxsize=1)
    @staticmethod
    def get_all() -> List["ReportType"]:
        result = []
        for reporter in get_all_reporters():
            result.extend(reporter.get_report_types())
        return result
