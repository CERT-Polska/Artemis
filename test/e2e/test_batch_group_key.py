import datetime
import socket
from datetime import timedelta
from test.e2e.base import BACKEND_URL, BaseE2ETestCase
from typing import List

import requests

from artemis.db import DB

API_TOKEN = "api-token"


class BatchGroupKeyE2ETestCase(BaseE2ETestCase):
    """
    Verifies that tasks with different requests_per_second_override values are placed
    in separate batches, observable through non-overlapping start_time windows.
    """

    def _submit_with_override(self, targets: List[str], tag: str, override: float) -> None:
        requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": targets,
                "tag": tag,
                "requests_per_second_override": override,
                "enabled_modules": ["port_scanner"],
            },
            headers={"X-API-Token": API_TOKEN},
        ).raise_for_status()

    def test_tasks_with_different_overrides_are_batched_separately(self) -> None:
        tag = "batch-key-override-e2e"

        group_a_ips = [
            socket.gethostbyname("test-service-with-bruteable-files-sql-dumps-replica1"),
            socket.gethostbyname("test-service-with-bruteable-files-sql-dumps-replica2"),
        ]
        group_b_ips = [
            socket.gethostbyname("test-service-with-bruteable-files-sql-dumps-replica3"),
            socket.gethostbyname("test-service-with-bruteable-files-sql-dumps-replica4"),
        ]
        group_a_override = 2.0
        group_b_override = 3.0

        self._submit_with_override(group_a_ips, tag, override=group_a_override)
        self._submit_with_override(group_b_ips, tag, override=group_b_override)

        self.wait_for_tasks_finished()

        group_a_times = []
        group_b_times = []
        for task_result in DB().get_paginated_task_results(0, 1000, []).data:
            pp = task_result["task"]["payload_persistent"]
            if task_result["task"]["headers"]["receiver"] != "port_scanner":
                continue
            if pp.get("tag") != tag:
                continue
            start_time = datetime.datetime.fromisoformat(task_result["task"]["payload"]["start_time"])
            override = pp.get("requests_per_second_override")
            if override == group_a_override:
                group_a_times.append(start_time)
            elif override == group_b_override:
                group_b_times.append(start_time)

        self.assertEqual(len(group_a_times), 2)
        self.assertEqual(len(group_b_times), 2)

        self.assertLess(max(group_a_times) - min(group_a_times), timedelta(seconds=2))
        self.assertLess(max(group_b_times) - min(group_b_times), timedelta(seconds=2))

        time_windows_not_overlaping = max(group_a_times) < min(group_b_times) or max(group_b_times) < min(group_a_times)
        self.assertTrue(
            time_windows_not_overlaping,
        )
