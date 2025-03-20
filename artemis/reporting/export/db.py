import datetime
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Optional, Set

from karton.core import Task
from tqdm import tqdm

from artemis.blocklist import BlocklistItem, blocklist_reports
from artemis.config import Config
from artemis.db import DB
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.reporters import reports_from_task_result
from artemis.reporting.severity import get_severity
from artemis.reporting.utils import get_top_level_target
from artemis.task_utils import get_target_host


class DataLoader:
    """
    A wrapper around DB that loads data and converts them to Reports.
    """

    def __init__(
        self,
        db: DB,
        blocklist: List[BlocklistItem],
        language: Language,
        tag: Optional[str],
        silent: bool = False,
    ):
        self._db = db
        self._blocklist = blocklist
        self._language = language
        self._tag = tag
        self._data_initialized = False
        self._silent = silent

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
        self._ips = {}
        self._hosts_with_waf_detected: Set[str] = set()
        self._scanned_top_level_targets = set()
        self._scanned_targets = set()
        self._tag_stats: DefaultDict[str, int] = defaultdict(lambda: 0)

        results = self._db.get_task_results_since(
            datetime.datetime.now() - datetime.timedelta(days=Config.Reporting.REPORTING_MAX_VULN_AGE_DAYS),
            tag=self._tag,
        )
        if not self._silent:
            results = tqdm(results)  # type: ignore

        for result in results:
            result_tag = result["task"].get("payload_persistent", {}).get("tag", None)
            self._tag_stats[result_tag] += 1

            try:
                top_level_target = get_top_level_target(result["task"])
            except ValueError:
                top_level_target = None

            if top_level_target:
                self._scanned_top_level_targets.add(top_level_target)

            if isinstance(result["result"], dict) and result["result"].get("waf_detected", False):
                self._hosts_with_waf_detected.add(DataLoader._get_target_host(result["task"]))

            if result["task"]["headers"]["receiver"] == "IPLookup":
                if isinstance(result.get("result", {}), dict):
                    self._ips[result["target_string"]] = list(result["result"].get("ips", []))

            self._scanned_targets.add(DataLoader._get_target_host(result["task"]))

            # The underlying data format changed, let's not require the reporters to change
            data_for_reporters = result["task"]
            data_for_reporters.update(result)

            reports_to_add = reports_from_task_result(data_for_reporters, self._language)
            for report_to_add in reports_to_add:
                report_to_add.tag = result_tag
                report_to_add.original_karton_name = result["task"]["headers"]["receiver"]
                report_to_add.original_task_result_id = result["id"]
                report_to_add.original_task_result_root_uid = result["analysis_id"]
                report_to_add.original_task_target_string = result["target_string"]
                report_to_add.severity = get_severity(report_to_add)
                report_to_add.normal_form = report_to_add.get_normal_form()
                report_to_add.last_domain = result["task"]["payload"].get("last_domain", None)

            self._reports.extend(blocklist_reports(reports_to_add, self._blocklist))
        self._data_initialized = True

    @property
    def reports(self) -> List[Report]:
        self._initialize_data_if_needed()
        return self._reports

    @property
    def ips(self) -> dict[str, List[str]]:
        self._initialize_data_if_needed()
        return self._ips

    @property
    def scanned_top_level_targets(self) -> Set[str]:
        self._initialize_data_if_needed()
        return self._scanned_top_level_targets

    @property
    def hosts_with_waf_detected(self) -> Set[str]:
        self._initialize_data_if_needed()
        return self._hosts_with_waf_detected

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
