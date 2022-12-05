import dataclasses
import json
from enum import Enum
from typing import Any, Dict, List, Optional, cast

from karton.core import Task
from pydantic import BaseModel
from pymongo import MongoClient

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config


class TaskFilter(str, Enum):
    INTERESTING_UNDECIDED = "INTERESTING_UNDECIDED"
    INTERESTING = "INTERESTING"


class ManualDecisionType(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSTIVE = "false_positive"


@dataclasses.dataclass
class TaskResultManualDecision:
    target_string: Optional[str]
    message: str
    decision_type: ManualDecisionType
    operator_comment: str


def get_task_target_as_string(task: Task) -> str:
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
        self.task_result_manual_decisions = self.client.artemis.task_result_manual_decisions
        self.scheduled_tasks = self.client.artemis.scheduled_tasks
        self.task_results = self.client.artemis.task_results

    def list_analysis(self) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], list(self.analysis.find()))

    def add_task_result_manual_decision(self, decision: TaskResultManualDecision) -> None:
        self.task_result_manual_decisions.insert_one(dataclasses.asdict(decision))

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
        created_task_result["target_string"] = get_task_target_as_string(task)
        created_task_result["status_reason"] = status_reason

        if isinstance(data, BaseModel):
            created_task_result["result"] = data.dict()
        elif isinstance(data, Exception):
            created_task_result["result"] = str(data)
        else:
            created_task_result["result"] = data

        self.task_results.update_one({"_id": created_task_result["uid"]}, {"$set": created_task_result}, upsert=True)

    def get_analysis_by_url(self, url: str) -> List[Dict[str, Any]]:
        return cast(List[Dict[str, Any]], self.analysis.find({"data": {"$regex": f".*{url}.*"}}))

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return cast(Optional[Dict[str, Any]], self.analysis.find_one({"_id": analysis_id}))

    def get_task_results_by_analysis_id(
        self, analysis_id: str, task_filter: Optional[TaskFilter] = None
    ) -> List[Dict[str, Any]]:
        if task_filter in [TaskFilter.INTERESTING, TaskFilter.INTERESTING_UNDECIDED]:
            task_results = cast(
                List[Dict[str, Any]],
                list(self.task_results.find({"root_uid": analysis_id, "status": TaskStatus.INTERESTING})),
            )
        else:
            assert task_filter is None

            task_results = cast(List[Dict[str, Any]], list(self.task_results.find({"root_uid": analysis_id})))

        decisions = self._get_decisions_for_task_results(task_results)
        task_results_filtered = []

        for task_result in task_results:
            decision = decisions.get(task_result["uid"], None)
            task_result["decision"] = decision

            if (task_filter == TaskFilter.INTERESTING_UNDECIDED and not decision) or (
                task_filter != TaskFilter.INTERESTING_UNDECIDED
            ):
                task_results_filtered.append(task_result)
        return task_results_filtered

    def get_undecided_task_results_by_analysis_id(self, analysis_id: str) -> List[Dict[str, Any]]:
        task_results = list(self.task_result_manual_decisions.find())
        decisions_for_task_results = self._get_decisions_for_task_results(task_results)

        task_results_filtered = []
        for task_result in task_results:
            if task_result["uid"] not in decisions_for_task_results:
                task_results_filtered.append(task_result)
        return task_results_filtered

    def get_task_by_id(self, task_id: str) -> Optional[Dict[str, Any]]:
        task_result = cast(Optional[Dict[str, Any]], self.task_results.find_one({"_id": task_id}))
        if task_result:
            task_result["decision"] = self._get_decision_for_task_result(task_result)
        return task_result

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

    def _get_decision_for_task_result(self, task_result: Dict[str, Any]) -> Optional[TaskResultManualDecision]:
        decision_dict = self.task_result_manual_decisions.find_one(
            {"message": task_result["status_reason"], "target_string": None}
        ) or self.task_result_manual_decisions.find_one(
            {"message": task_result["status_reason"], "target_string": task_result["target_string"]}
        )

        if decision_dict:
            del decision_dict["_id"]
            return TaskResultManualDecision(**decision_dict)
        else:
            return None

    def _get_decisions_for_task_results(
        self, task_results: List[Dict[str, Any]]
    ) -> Dict[str, TaskResultManualDecision]:
        decisions_for_message = {}
        decisions_for_message_and_target = {}

        for obj in self.task_result_manual_decisions.find():
            del obj["_id"]
            decision = TaskResultManualDecision(**obj)

            if decision.target_string:
                decisions_for_message_and_target[(decision.message, decision.target_string)] = decision
            else:
                decisions_for_message[decision.message] = decision

        decisions = {}
        for task_result in task_results:
            found_decision: Optional[TaskResultManualDecision] = None

            if task_result["status_reason"] in decisions_for_message:
                found_decision = decisions_for_message[task_result["status_reason"]]

            if (task_result["status_reason"], task_result["target_string"]) in decisions_for_message_and_target:
                found_decision = decisions_for_message_and_target[
                    (task_result["status_reason"], task_result["target_string"])
                ]

            if found_decision:
                decisions[task_result["uid"]] = found_decision
        return decisions
