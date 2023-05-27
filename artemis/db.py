import dataclasses
import datetime
import json
from enum import Enum
from typing import Any, Dict, Generator, List, Optional, Tuple, cast

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
    INTERESTING = "interesting"

    def as_dict(self) -> Dict[str, Any]:
        if self.value == TaskFilter.INTERESTING.value:
            return {"status": "INTERESTING"}
        else:
            assert False


@dataclasses.dataclass
class PaginatedResults:
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
    elif task.headers["type"] == TaskType.URL:
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
        self.scheduled_tasks = self.client.artemis.scheduled_tasks
        self.task_results = self.client.artemis.task_results
        self.statistics = self.client.artemis.statistics
        self.logger = build_logger(__name__)

    def list_analysis(self) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], list(self.analysis.find()))

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

        with self.client.start_session() as session:
            with session.start_transaction():
                result = self.task_results.update_one(
                    upsert=True, filter={"_id": created_task_result["uid"]}, update={"$set": created_task_result}
                )
                if result.upserted_id:  # If the record has been created, set creation date
                    result = self.task_results.update_one(
                        {"_id": created_task_result["uid"]}, {"$set": {"created_at": datetime.datetime.now()}}
                    )

    def get_analysis_by_url(self, url: str) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], self.analysis.find({"data": {"$regex": f".*{url}.*"}}))

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return cast(Optional[Dict[str, Any]], self.analysis.find_one({"_id": analysis_id}))

    def get_paginated_analyses(
        self,
        start: int,
        length: int,
        ordering: List[ColumnOrdering],
        *,
        search_query: Optional[str] = None,
    ) -> PaginatedResults:
        filter_dict: Dict[str, Any] = {}

        ordering_pymongo = [
            (ordering_rule.column_name, ASCENDING if ordering_rule.ascending else DESCENDING)
            for ordering_rule in ordering
        ]

        records_count_total = self.analysis.estimated_document_count()
        if search_query:
            filter_dict.update({"$text": {"$search": self._to_mongo_query(search_query)}})
        records_count_filtered = self.analysis.count_documents(filter_dict)
        results_page = self.analysis.find(filter_dict).sort(ordering_pymongo)[start : start + length]
        return PaginatedResults(
            records_count_total=records_count_total,
            records_count_filtered=records_count_filtered,
            data=cast(List[Dict[str, Any]], results_page),
        )

    def get_paginated_task_results(
        self,
        start: int,
        length: int,
        ordering: List[ColumnOrdering],
        fields: List[str],
        *,
        search_query: Optional[str] = None,
        analysis_id: Optional[str] = None,
        task_filter: Optional[TaskFilter] = None,
    ) -> PaginatedResults:
        filter_dict: Dict[str, Any] = {}
        if analysis_id:
            filter_dict["root_uid"] = analysis_id

        if task_filter:
            filter_dict.update(task_filter.as_dict())

        ordering_pymongo = [
            (ordering_rule.column_name, ASCENDING if ordering_rule.ascending else DESCENDING)
            for ordering_rule in ordering
        ]

        records_count_total = self.task_results.estimated_document_count()
        if search_query:
            filter_dict.update({"$text": {"$search": self._to_mongo_query(search_query)}})
        records_count_filtered = self.task_results.count_documents(filter_dict)
        results_page = self.task_results.find(filter_dict, {field: 1 for field in fields}).sort(ordering_pymongo)[
            start : start + length
        ]
        return PaginatedResults(
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
            "uid": task.uid,
            "created_at": datetime.datetime.now(),
            "analysis_id": task.root_uid,
            "deduplication_data": self._get_task_deduplication_data(task),
        }
        result = self.scheduled_tasks.update_one(
            {
                "analysis_id": created_task["analysis_id"],
                "deduplication_data": created_task["deduplication_data"],
            },
            {"$set": created_task},
            upsert=True,
        )
        return bool(result.upserted_id)

    def get_task_results_since(self, time_from: datetime.datetime) -> Generator[Dict[str, Any], None, None]:
        with self.client.start_session() as session:
            try:
                cursor = self.task_results.find(
                    {"created_at": {"$gte": time_from}}, no_cursor_timeout=True, session=session
                ).batch_size(1)
                for item in cursor:
                    yield cast(Dict[str, Any], item)
            finally:
                cursor.close()

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
        self.statistics.find_one_and_update({"name": name, "value": value}, {"$inc": {"count": 1}}, upsert=True)

    def initialize_database(self) -> None:
        """Creates MongoDB indexes. create_index() creates an index if it doesn't exist, so
        this method will not recreate existing indexes."""
        self.task_results.create_index(
            [
                ("target_string", ASCENDING),
                ("status_reason", ASCENDING),
            ]
        )
        self.task_results.create_index([("status_reason", ASCENDING)])
        self.task_results.create_index([("status", ASCENDING)])
        self.task_results.create_index(
            [
                ("status", "text"),
                ("priority", "text"),
                ("payload_persistent.tag", "text"),
                ("target_string", "text"),
                ("headers_string", "text"),
                ("status_reason", "text"),
            ],
            name="fulltext",
        )
        self.analysis.create_index(
            [
                ("payload.data", "text"),
                ("payload_persistent.tag", "text"),
            ],
            name="analysis_fulltext",
        )

        for statistic in statistics.STATISTICS:
            self.statistics.update_one(
                upsert=True,
                filter={"name": statistic["name"], "value": statistic["value"]},
                update={"$setOnInsert": {"count": statistic["count"]}},
            )

    def _to_mongo_query(self, query: str) -> str:
        """Converts a space-separated query (e.g. directory_index wp-content) to a MongoDB query
        that requires all words to be present (in that case it would be "directory_index" AND "wp-content").
        """

        query = query.replace("\\", " ")  # just in case
        query = query.replace('"', " ")  # just in case
        return " AND ".join([f'"{item}"' for item in query.split(" ") if item])
