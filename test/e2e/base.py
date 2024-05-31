import time
from collections import namedtuple
from typing import Any, Dict, List
from unittest import TestCase

import requests
from bs4 import BeautifulSoup
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig

from artemis.db import DB, Analysis, ReportGenerationTask, ScheduledTask, TaskResult
from artemis.utils import build_logger

BACKEND_URL = "http://web:5000/"
NUM_RETRIES = 100
RETRY_TIME_SECONDS = 2


TaskListRow = namedtuple("TaskListRow", ["created_at", "tag", "receiver", "task_link", "headers_html", "message"])


class BaseE2ETestCase(TestCase):
    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)

        self._logger = build_logger(__name__)

    def setUp(self) -> None:
        self._wait_for_backend()

        db = DB()
        session = db.session()
        session.query(ScheduledTask).delete()
        session.query(Analysis).delete()
        session.query(ReportGenerationTask).delete()
        session.query(TaskResult).delete()
        session.commit()

        backend = KartonBackend(config=KartonConfig())

        for key in backend.redis.keys("karton.task*"):
            backend.redis.delete(key)

        for key in backend.redis.keys("karton.queue*"):
            backend.redis.delete(key)

    def submit_tasks(self, tasks: List[str], tag: str) -> None:
        with requests.Session() as s:
            response = s.get(BACKEND_URL + "add")
            data = response.content
            soup = BeautifulSoup(data, "html.parser")
            csrf_token = soup.find("input", {"name": "csrf_token"})["value"]  # type: ignore
            response = s.post(
                BACKEND_URL + "add",
                data={
                    "csrf_token": csrf_token,
                    "priority": "normal",
                    "targets": "\n".join(tasks),
                    "tag": tag,
                },
            )
            response.raise_for_status()

    def submit_tasks_with_modules_enabled(self, tasks: List[str], tag: str, modules_enabled: List[str]) -> None:
        with requests.Session() as s:
            data = s.get(BACKEND_URL + "add").content
            soup = BeautifulSoup(data, "html.parser")
            csrf_token = soup.find("input", {"name": "csrf_token"})["value"]  # type: ignore

            response = s.post(
                BACKEND_URL + "add",
                data={
                    "csrf_token": csrf_token,
                    "priority": "normal",
                    "targets": "\n".join(tasks),
                    "tag": tag,
                    "choose_modules_to_enable": True,
                    **{f"module_enabled_{module}": True for module in modules_enabled},
                },
            )
            response.raise_for_status()

    def wait_for_tasks_finished(
        self, retry_time_seconds: float = RETRY_TIME_SECONDS, num_retries: int = NUM_RETRIES
    ) -> None:
        for retry in range(num_retries):
            if "pending tasks: 0\n" in requests.get(BACKEND_URL).content.decode("utf-8"):
                return
            self._logger.info("There are still pending tasks, retrying")
            time.sleep(retry_time_seconds)

    def get_task_results(self) -> Dict[str, Any]:
        return requests.get(  # type: ignore
            BACKEND_URL
            + "api/task-results-table?draw=1&start=0&length=100&order%5B0%5D%5Bcolumn%5D=0&order%5B0%5D%5Bdir%5D=asc&search[regex]=false&search[value]="
        ).json()

    def get_task_messages(self, tag: str) -> List[str]:
        task_results = self.get_task_results()["data"]
        messages = []
        for task_result in task_results:
            task_result = TaskListRow(*task_result)
            if task_result.tag == tag and task_result.message:
                messages.append(task_result.message)
        return messages

    # These methods have camelCase names for consistency with other unittest methods
    def assertMessagesContain(self, tag: str, message: str) -> None:
        messages = self.get_task_messages(tag)
        self.assertIn(message, messages)

    def assertMessagesEmpty(self, tag: str) -> None:
        messages = self.get_task_messages(tag)
        self.assertFalse(messages)

    def _wait_for_backend(self, retry_time_seconds: float = RETRY_TIME_SECONDS, num_retries: int = NUM_RETRIES) -> None:
        for retry in range(num_retries):
            try:
                response = requests.get(BACKEND_URL)

                if response.status_code == 200:
                    return
                else:
                    self._logger.error(
                        "Non-200 response code: %d when trying to access backend: try %d/%d",
                        response.status_code,
                        retry + 1,
                        num_retries,
                    )
            except Exception as e:
                self._logger.error("Error when trying to access backend: %s try %d/%d", e, retry + 1, num_retries)
            time.sleep(retry_time_seconds)
