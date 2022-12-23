import time
from typing import Any, Dict, List
from unittest import TestCase

import requests

from artemis.utils import build_logger

BACKEND_URL = "http://backend:5000/"
NUM_RETRIES = 100
RETRY_TIME_SECONDS = 2


class BaseE2ETestCase(TestCase):
    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)

        self._logger = build_logger(__name__)

    def setUp(self) -> None:
        self._wait_for_backend()

    def submit_tasks(self, tasks: List[str]) -> None:
        requests.post(BACKEND_URL + "add", data={"urls": "\n".join(tasks)})

    def wait_for_tasks_finished(
        self, retry_time_seconds: float = RETRY_TIME_SECONDS, num_retries: int = NUM_RETRIES
    ) -> None:
        for retry in range(num_retries):
            if "pending tasks:" not in requests.get(BACKEND_URL).content.decode("utf-8"):
                return
            self._logger.info("There are still pending tasks, retrying")
            time.sleep(retry_time_seconds)

    def get_task_results(self) -> Dict[str, Any]:
        return requests.get(  # type: ignore
            BACKEND_URL + "api/task-results?draw=1&start=0&length=100&order[0][column]=0&order[0][dir]=asc"
        ).json()

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
