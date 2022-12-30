import dataclasses
import datetime
import json
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, cast

from karton.core import Task
from pydantic import BaseModel
from pymongo import ASCENDING, DESCENDING, MongoClient

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.modules.data import statistics
from artemis.utils import build_logger


@dataclasses.dataclass
class ColumnOrdering:
    column_name: str
    ascending: bool


class TaskFilter(str, Enum):
    INTERESTING_UNDECIDED = "interesting_undecided"
    INTERESTING = "interesting"
    APPROVED = "approved"
    DISMISSED = "dismissed"

    def as_dict(self) -> Dict[str, Any]:
        if self.value == TaskFilter.INTERESTING_UNDECIDED:
            return {"status": "INTERESTING", "decision_type": None}
        elif self.value == TaskFilter.INTERESTING:
            return {"status": "INTERESTING"}
        elif self.value == TaskFilter.APPROVED:
            return {"decision_type": "approved"}
        elif self.value == TaskFilter.DISMISSED:
            return {"decision_type": "dismissed"}
        else:
            assert False


class ManualDecisionType(str, Enum):
    APPROVED = "approved"
    DISMISSED = "dismissed"


@dataclasses.dataclass
class ManualDecision:
    target_string: Optional[str]
    message: str
    decision_type: ManualDecisionType
    operator_comment: Optional[str]


@dataclasses.dataclass
class PaginatedTaskResults:
    records_count_total: int
    records_count_filtered: int
    data: List[Dict[str, Any]]


def get_task_target(task: Task) -> str:
    result = None
    if task.headers["type"] == TaskType.NEW:
        result = task.payload.get("data", None)
    elif task.headers["type"] == TaskType.IP:
        result = task.payload.get("ip", None)
    elif task.headers["type"] == TaskType.DOMAIN:
        result = task.payload.get("domain", None)
    elif task.headers["type"] == TaskType.WEBAPP:
        result = task.payload.get("url", None)
    elif task.headers["type"] == TaskType.SERVICE:
        if "host" in task.payload and "port" in task.payload:
            result = task.payload["host"] + ":" + str(task.payload["port"])

    if not result:
        result = task.headers["type"] + ": " + task.uid

    assert isinstance(result, str)
    return result


class DB:
    def __init__(self) -> None:
        self.client = MongoClient(Config.DB_CONN_STR)
        self.analysis = self.client.artemis.analysis
        self.manual_decisions = self.client.artemis.manual_decisions
        self.scheduled_tasks = self.client.artemis.scheduled_tasks
        self.task_results = self.client.artemis.task_results
        self.statistics = self.client.artemis.statistics
        self.logger = build_logger(__name__)

    def list_analysis(self) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], list(self.analysis.find()))

    def add_manual_decision(self, decision: ManualDecision) -> None:
        self.manual_decisions.insert_one(dataclasses.asdict(decision))
        self._apply_manual_decisions()

    def create_analysis(self, analysis: Task) -> None:
        created_analysis = self.task_to_dict(analysis)

        created_analysis["_id"] = created_analysis["uid"]
        del created_analysis["status"]
        if "status_reason" in created_analysis:
            del created_analysis["status_reason"]
        self.analysis.insert_one(created_analysis)

    def save_task_result(
        self, task: Task, *, status: TaskStatus, status_reason: Optional[str] = None, data: Optional[Any] = None
    ) -> None:
        created_task_result = self.task_to_dict(task)

        created_task_result["_id"] = created_task_result["uid"]
        created_task_result["status"] = status
        created_task_result["target_string"] = get_task_target(task)
        created_task_result["status_reason"] = status_reason

        # Used to allow searching in the names and values of all existing headers
        created_task_result["headers_string"] = " ".join([key + " " + value for key, value in task.headers.items()])

        if isinstance(data, BaseModel):
            created_task_result["result"] = data.dict()
        elif isinstance(data, Exception):
            created_task_result["result"] = str(data)
        else:
            created_task_result["result"] = data

        result = self.task_results.update_one(
            upsert=True, filter={"_id": created_task_result["uid"]}, update={"$set": created_task_result}
        )
        if result.upserted_id:  # If the record has been created, set creation date
            result = self.task_results.update_one(
                {"_id": created_task_result["uid"]}, {"$set": {"created_at": datetime.datetime.now()}}
            )

        self._apply_manual_decisions()

    def get_analysis_by_url(self, url: str) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], self.analysis.find({"data": {"$regex": f".*{url}.*"}}))

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return cast(Optional[Dict[str, Any]], self.analysis.find_one({"_id": analysis_id}))

    def get_paginated_task_results(
        self,
        start: int,
        length: int,
        ordering: List[ColumnOrdering],
        *,
        search_query: Optional[str] = None,
        analysis_id: Optional[str] = None,
        task_filter: Optional[TaskFilter] = None,
    ) -> PaginatedTaskResults:
        filter_dict: Dict[str, Any] = {}
        if analysis_id:
            filter_dict["root_uid"] = analysis_id

        if task_filter:
            filter_dict.update(task_filter.as_dict())

        ordering_pymongo = [
            (ordering_rule.column_name, ASCENDING if ordering_rule.ascending else DESCENDING)
            for ordering_rule in ordering
        ]

        records_count_total = self.task_results.count_documents(filter_dict)
        if search_query:
            filter_dict.update({"$text": {"$search": search_query}})
        records_count_filtered = self.task_results.count_documents(filter_dict)
        results_page = self.task_results.find(filter_dict).sort(ordering_pymongo)[start : start + length]
        return PaginatedTaskResults(
            records_count_total=records_count_total,
            records_count_filtered=records_count_filtered,
            data=cast(List[Dict[str, Any]], results_page),
        )

    def get_task_by_id(self, task_id: str) -> Optional[Dict[str, Any]]:
        return cast(Optional[Dict[str, Any]], self.task_results.find_one({"_id": task_id}))

    def save_scheduled_task(self, task: Task) -> bool:
        """
        Saves a scheduled task and returns True if it didn't exist in the database.

        The purpose of this method is deduplication - making sure identical tasks aren't run twice.
        """
        created_task = {
            "analysis_id": task.root_uid,
            "deduplication_data": self._get_task_deduplication_data(task),
        }
        result = self.scheduled_tasks.update_one(created_task, {"$set": created_task}, upsert=True)
        return bool(result.upserted_id)

    def _get_task_deduplication_data(self, task: Task) -> List[List[Any]]:
        """
        Represents a task so that two identical tasks with different IDs will have the same representation.

        Instead of dictionaries, lists are used (so that e.g. {"domain": "google.com"} becomes
        [["domain", "google.com"]] to prevent ordering problems (as MongoDB compares dictionaries in
        an ordered way).
        """

        def dict_to_list(d: Dict[str, Any]) -> List[List[Any]]:
            result = []
            # We sort the items so that the same dict will always have the same representation
            # regardless of how are the items ordered internally.
            for key, value in sorted(d.items()):
                if isinstance(value, dict):
                    result.append([key, dict_to_list(value)])
                else:
                    result.append([key, value])
            return result

        # We convert the task to dict so that we don't have problems e.g. with enums.
        task_as_dict = self.task_to_dict(task)

        # We treat a task that originates from a different karton than an existing one
        # as an existing one.
        if "origin" in task_as_dict["headers"]:
            del task_as_dict["headers"]["origin"]
        if "receiver" in task_as_dict["headers"]:
            del task_as_dict["headers"]["receiver"]

        return dict_to_list(
            {
                "headers": task_as_dict["headers"],
                "payload": task_as_dict["payload"],
                "payload_persistent": task_as_dict["payload_persistent"],
            }
        )

    def task_to_dict(self, task: Task) -> Dict[str, Any]:
        # TODO make this less ugly
        return json.loads(task.serialize())  # type: ignore

    def get_top_for_statistic(self, name: str, count: int) -> List[Tuple[int, str]]:
        result = []
        for item in self.statistics.find({"name": name}).sort("count", DESCENDING)[:count]:
            result.append((item["count"], item["value"]))
        return result

    def statistic_increase(self, name: str, value: str) -> None:
        self.statistics.find_one_and_update({"name": name, "value": value}, {"$inc": {"count": 1}})

    def initialize_database(self) -> None:
        """Creates MongoDB indexes. create_index() creates an index if it doesn't exist, so
        this method will not recreate existing indexes."""
        self.task_results.create_index(
            [
                ("target_string", ASCENDING),
                ("status_reason", ASCENDING),
                ("decision_type", ASCENDING),
            ]
        )
        self.task_results.create_index([("status_reason", ASCENDING), ("decision_type", ASCENDING)])
        self.task_results.create_index([("status", ASCENDING)])
        self.task_results.create_index(
            [
                ("status", "text"),
                ("priority", "text"),
                ("target_string", "text"),
                ("headers_string", "text"),
                ("status_reason", "text"),
                ("decision_type", "text"),
                ("operator_comment", "text"),
            ],
        )

        for statistic in statistics.STATISTICS:
            self.statistics.update_one(
                upsert=True,
                filter={"name": statistic["name"], "value": statistic["value"]},
                update={"$setOnInsert": {"count": statistic["count"]}},
            )

    def _get_decision(self, task_result: Dict[str, Any]) -> Optional[ManualDecision]:
        decision_dict = self.manual_decisions.find_one(
            {"message": task_result["status_reason"], "target_string": None}
        ) or self.manual_decisions.find_one(
            {"message": task_result["status_reason"], "target_string": task_result["target_string"]}
        )

        if decision_dict:
            del decision_dict["_id"]
            return ManualDecision(**decision_dict)
        else:
            return None

    def _apply_manual_decisions(self) -> None:
        time_start = time.time()
        for manual_decision in self.manual_decisions.find():
            del manual_decision["_id"]
            manual_decision_obj = ManualDecision(**manual_decision)

            decision_data = {
                "decision_type": manual_decision_obj.decision_type,
                "operator_comment": manual_decision_obj.operator_comment,
            }
            if manual_decision_obj.target_string:
                self.task_results.update_many(
                    {
                        "target_string": manual_decision_obj.target_string,
                        "status_reason": manual_decision_obj.message,
                        "decision_type": None,
                    },
                    {"$set": decision_data},
                )
            else:
                self.task_results.update_many(
                    {"status_reason": manual_decision_obj.message, "decision_type": None}, {"$set": decision_data}
                )
        self.logger.info("Manual decisions applied for existing tasks in %.02fs", time.time() - time_start)
