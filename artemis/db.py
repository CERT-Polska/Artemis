import json
from typing import Any, Dict, List, Optional, cast

from karton.core import Task
from pydantic import BaseModel
from pymongo import MongoClient

from artemis.binds import TaskStatus
from artemis.config import Config


class DB:
    def __init__(self) -> None:
        self.client = MongoClient(Config.DB_CONN_STR)
        self.analysis = self.client.artemis.analysis
        self.scheduled_tasks = self.client.artemis.scheduled_tasks
        self.task_results = self.client.artemis.task_results

    def list_analysis(self) -> List[Dict]:
        return cast(List[Dict], list(self.analysis.find()))

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
        created_task_result["status_reason"] = status_reason

        if isinstance(data, BaseModel):
            created_task_result["result"] = data.dict()
        elif isinstance(data, Exception):
            created_task_result["result"] = str(data)
        else:
            created_task_result["result"] = data

        self.task_results.update_one({"_id": created_task_result["uid"]}, {"$set": created_task_result}, upsert=True)

    def get_analysis_by_url(self, url: str) -> List[Dict]:
        return cast(List[Dict], self.analysis.find({"data": {"$regex": f".*{url}.*"}}))

    def get_analysis_by_id(self, analysis_id: str) -> Optional[Dict]:
        return cast(Optional[Dict], self.analysis.find_one({"_id": analysis_id}))

    def get_task_results_by_analysis_id(self, analysis_id: str, status: Optional[str] = None) -> List[Dict]:
        if status:
            return cast(
                List[Dict], list(self.task_results.find({"root_uid": analysis_id, "status": TaskStatus(status)}))
            )
        else:
            return cast(List[Dict], list(self.task_results.find({"root_uid": analysis_id})))

    def get_task_by_id(self, task_id: str) -> Optional[Dict]:
        return cast(Optional[Dict], self.task_results.find_one({"_id": task_id}))

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

    def _get_task_deduplication_data(self, task: Task) -> List:
        """
        Represents a task so that two identical tasks with different IDs will have the same representation.

        Instead of dictionaries, lists are used (so that e.g. {"domain": "google.com"} becomes
        [["domain", "google.com"]] to prevent ordering problems (as MongoDB compares dictionaries in
        an ordered way).
        """

        def dict_to_list(d: dict) -> List:
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

    def task_to_dict(self, task: Task) -> dict:
        # TODO make this less ugly
        return json.loads(task.serialize())
