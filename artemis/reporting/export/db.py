import datetime
import urllib
from collections import defaultdict
from typing import DefaultDict, Dict, List, Set

from tqdm import tqdm

from artemis.config import Config
from artemis.db import DB
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.reporters import reports_from_task_result
from artemis.reporting.blocklist import BlocklistItem, filter_blocklist
from artemis.reporting.utils import get_top_level_target_if_present


class ExportDBConnector:
    """
    A wrapper around DB that loads data and converts them to Reports.
    """

    def __init__(self, db: DB, blocklist: List[BlocklistItem], language: Language, tag: str):
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

            if result_tag != self._tag:
                continue

            top_level_target = get_top_level_target_if_present(task_result)
            if top_level_target:
                self._scanned_top_level_targets.add(top_level_target)

            self._scanned_targets.add(ExportDBConnector._get_domain_or_ip_only(task_result["target_string"]))
            reports_to_add = reports_from_task_result(task_result, self._language)
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
    def _get_domain_or_ip_only(data: str) -> str:
        """Extracts domain/ip from URL or host:port string."""
        if "://" in data:
            host = urllib.parse.urlparse(data).hostname
            if not host:
                raise ValueError(f"No hostname in {data}")
            return host
        if ":" in data:
            host = urllib.parse.urlparse("//" + data).hostname
            if not host:
                raise ValueError(f"No hostname in {data}")
            return host
        return data
