import unittest
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.module_base import ArtemisBase
from artemis.task_utils import LAST_CONSUMED_TASK_TIME_KEY


class TaskConsumptionHealthTest(unittest.TestCase):
    def test_timestamp_tracks_dequeued_tasks_including_skipped_tasks(self) -> None:
        for task_count, blocklisted in [(0, False), (1, False), (2, False), (1, True)]:
            with self.subTest(task_count=task_count, blocklisted=blocklisted):
                worker = MagicMock()
                worker.identity = "test-worker"
                worker.queue_location_max_age_seconds = 60
                worker.lock_target = False
                worker.backend.get_queue_names.return_value = ["test-queue"]
                tasks = [Task({"type": "domain"}, payload={"domain": "example.com"}) for _ in range(task_count)]
                worker.backend.redis.lrange.return_value = [task.uid for task in tasks]
                worker.backend.get_task.side_effect = tasks
                worker._is_blocklisted.return_value = blocklisted
                with (
                    patch("artemis.module_base.REDIS") as redis,
                    patch("artemis.module_base.time.time", return_value=100000),
                    patch("artemis.module_base.increase_analysis_num_finished_tasks"),
                ):
                    redis.get.return_value = None
                    returned_tasks, _, consumed = ArtemisBase._take_and_lock_tasks(worker, 2)

                self.assertEqual(consumed, task_count)
                self.assertEqual(len(returned_tasks), 0 if blocklisted else task_count)
                writes = [call for call in redis.hset.call_args_list if call.args[0] == LAST_CONSUMED_TASK_TIME_KEY]
                self.assertEqual(len(writes), 1 if task_count else 0)
                if task_count:
                    self.assertEqual(writes[0].args[1:], ("test-worker", 100000))
