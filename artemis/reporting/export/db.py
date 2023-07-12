import datetime
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Optional, Set

from karton.core import Task
from tqdm import tqdm

from artemis.config import Config
from artemis.db import DB
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.reporters import reports_from_task_result
from artemis.reporting.blocklist import BlocklistItem, filter_blocklist
from artemis.reporting.utils import get_top_level_target
from artemis.task_utils import get_target_host


class DataLoader:
    """
    A wrapper around DB that loads data and converts them to Reports.
    """

    def __init__(self, db: DB, blocklist: List[BlocklistItem], language: Language, tag: Optional[str]):
        self._db = db
        self._blocklist = blocklist
        self._language = language
        self._tag = tag
        self._data_initialized = False

    def _initialize_data_if_needed(self) -> None:
        """
        Because going through the data takes a long time, we want to do at most one pass and
        save the results in instance variables.

        This happens transparently - data initialization will happen on the first access of any
        property.
        """
        if self._data_initialized:
            return

        self._reports = []
        self._scanned_top_level_targets = set()
        self._scanned_targets = set()
        self._tag_stats: DefaultDict[str, int] = defaultdict(lambda: 0)

        for task_result in tqdm(
            self._db.get_task_results_since(
                datetime.datetime.now() - datetime.timedelta(days=Config.REPORTING_MAX_VULN_AGE_DAYS)
            )
        ):
            result_tag = task_result.get("payload_persistent", {}).get("tag", None)
            self._tag_stats[result_tag] += 1

            if self._tag and result_tag != self._tag:
                continue

            try:
                top_level_target = get_top_level_target(task_result)
            except ValueError:
                top_level_target = None

            if top_level_target:
                self._scanned_top_level_targets.add(top_level_target)

            self._scanned_targets.add(DataLoader._get_target_host(task_result))
            reports_to_add = reports_from_task_result(task_result, self._language)
            for report_to_add in reports_to_add:
                report_to_add.tag = result_tag
                report_to_add.original_karton_name = task_result["headers"]["receiver"]
                report_to_add.original_task_result_id = task_result["_id"]
                report_to_add.original_task_target_string = task_result["target_string"]

            self._reports.extend(filter_blocklist(reports_to_add, self._blocklist))
        self._data_initialized = True

    @property
    def reports(self) -> List[Report]:
        self._initialize_data_if_needed()
        return self._reports

    @property
    def scanned_top_level_targets(self) -> Set[str]:
        self._initialize_data_if_needed()
        return self._scanned_top_level_targets

    @property
    def scanned_targets(self) -> Set[str]:
        self._initialize_data_if_needed()
        return self._scanned_targets

    @property
    def tag_stats(self) -> Dict[str, int]:
        self._initialize_data_if_needed()
        return self._tag_stats

    @staticmethod
    def _get_target_host(data: Dict[str, Any]) -> str:
        """Extracts domain/ip from task."""
        return get_target_host(Task(headers=data["headers"], payload=data["payload"]))
