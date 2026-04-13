import datetime
import socket
from test.e2e.base import BaseE2ETestCase


class BruterParallelizationE2ETestCase(BaseE2ETestCase):
    def tes_bruter_parallelization(self) -> None:
        ips = [
            socket.gethostbyname("test-service-with-bruteable-files-sql-dumps-replica%d" % i) for i in [1, 2, 3, 4, 5]
        ]
        self.submit_tasks_with_modules_enabled(ips, "bruter-parallelization", ["bruter"])
        self.wait_for_tasks_finished()

        num_bruter_results = 0
        task_results = self.get_task_results()["data"]
        start_times = []
        for task_result in task_results:
            if task_result["headers"]["receiver"] == "bruter" and task_result["payload_persistent"]["tag"] == "bruter-parallelization":
                num_bruter_results += 1
                start_times.append(task_results["payload"]["created_at"])
        print("AAAAAA", task_results, start_times, num_bruter_results)
        self.assertEqual(num_bruter_results, 5)
        self.assertTrue(max(start_times) - min(start_times) < datetime.timedelta(seconds=5))

        for ip in ips:
            self.assertMessagesContain(tag, "Found URLs: http://%s:80/localhost.sql" % ip)
