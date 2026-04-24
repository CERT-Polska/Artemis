import datetime
import socket
from test.e2e.base import BaseE2ETestCase

from artemis.db import DB


class BruterParallelizationE2ETestCase(BaseE2ETestCase):
    def test_bruter_parallelization(self) -> None:
        tag = "bruter-parallelization"
        targets = [
            socket.gethostbyname("test-service-with-bruteable-files-sql-dumps-replica%d" % i) + ":80"
            for i in [1, 2, 3, 4, 5]
        ]
        self.submit_tasks_with_modules_enabled(targets, tag, ["bruter", "port_scanner"])
        self.wait_for_tasks_finished()

        num_bruter_results = 0
        start_times = []
        for task_result in DB().get_paginated_task_results(0, 1000, []).data:
            if (
                task_result["task"]["headers"]["receiver"] == "bruter"
                and task_result["task"]["payload_persistent"]["tag"] == tag
            ):
                num_bruter_results += 1
                start_times.append(datetime.datetime.fromisoformat(task_result["task"]["payload"]["start_time"]))

        self.assertEqual(num_bruter_results, 5)
        self.assertTrue(max(start_times) - min(start_times) < datetime.timedelta(seconds=5))

        for target in targets:
            self.assertMessagesContain(tag, "Found URLs: http://%s/localhost.sql" % target)
