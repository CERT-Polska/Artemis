import abc
import random
import sys
import time
import traceback
from typing import Any, List, Optional

from karton.core import Task
from karton.core.backend import KartonMetrics
from karton.core.task import TaskState

from artemis.binds import TaskStatus
from artemis.db import DB
from artemis.module_base import ArtemisBase


class ArtemisMultipleTasksBase(ArtemisBase):
    seconds_between_polling = 10
    batch_size = 100

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(db, *args, **kwargs)
        self._get_random_queue_element = self.backend.redis.register_script(
            """
            local random_seed = ARGV[1]
            local queue_name = ARGV[2]

            local length = redis.call('LLEN', queue_name)

            if length == 0 or length == nil then
                return nil
            end

            math.randomseed(random_seed)
            local member_id = math.random(length) - 1

            local values = redis.call('LRANGE', queue_name, member_id, member_id)
            redis.call('LREM', queue_name, 1, values[1])
            return values[1]
        """
        )

    @abc.abstractmethod
    def run_multiple(self, tasks: List[Task]) -> None:
        raise NotImplementedError()

    def loop(self) -> None:
        self.log.info("Service %s started", self.identity)

        # Get the old binds and set the new ones atomically
        old_bind = self.backend.register_bind(self._bind)

        if not old_bind:
            self.log.info("Service binds created.")
        elif old_bind != self._bind:
            self.log.info("Binds changed, old service instances should exit soon.")

        for task_filter in self.filters:
            self.log.info("Binding on: %s", task_filter)

        self.backend.set_consumer_identity(self.identity)

        try:
            while not self.shutdown:
                if self.backend.get_bind(self.identity) != self._bind:
                    self.log.info("Binds changed, shutting down.")
                    break
                tasks = self._consume_routed_tasks(self.identity, self.batch_size)
                if tasks:
                    self._process_tasks(tasks)
                else:
                    time.sleep(self.seconds_between_polling)
        except KeyboardInterrupt as e:
            self.log.info("Hard shutting down!")
            raise e

    def _process_tasks(self, tasks: List[Task]) -> None:
        tasks_filtered = []
        for task in tasks:
            if not task.matches_filters(self.filters):
                self.log.info("Task rejected because binds are no longer valid.")
                self.backend.set_task_status(task, TaskState.FINISHED)
                # Task rejected: end of processing
            else:
                tasks_filtered.append(task)

        tasks = tasks_filtered
        task_uids = ", ".join([task.uid for task in tasks])

        exception_str = None

        try:
            self.log.info("Received new tasks - %s", task_uids)
            for task in tasks:
                self.backend.set_task_status(task, TaskState.STARTED)

            self._run_pre_hooks()

            saved_exception = None
            try:
                self.run_multiple(tasks)
            except Exception as exc:
                for task in tasks:
                    self.db.save_task_result(task=task, status=TaskStatus.ERROR, data=traceback.format_exc())
                saved_exception = exc
                raise
            finally:
                self._run_post_hooks(saved_exception)

            self.log.info("Tasks done - %s", task_uids)
        except Exception:
            exc_info = sys.exc_info()
            exception_str = traceback.format_exception(*exc_info)

            self._increment_metrics_by(KartonMetrics.TASK_CRASHED, self.identity, len(tasks))
            self.log.exception("Failed to process tasks - %s", task_uids)
        finally:
            self._increment_metrics_by(KartonMetrics.TASK_CONSUMED, self.identity, len(tasks))

            for task in tasks:
                task_state = TaskState.FINISHED

                # report the task status as crashed
                # if an exception was caught while processing
                if exception_str is not None:
                    task_state = TaskState.CRASHED
                    task.error = exception_str

                self.backend.set_task_status(task, task_state)

    def _consume_routed_tasks(self, identity: str, max_count: int) -> List[Task]:
        task_uids: List[str] = []
        while len(task_uids) < max_count:
            added = False

            for queue in self.backend.get_queue_names(identity):
                if len(task_uids) == max_count:
                    break

                uid = self._get_random_queue_element(args=[random.randint(0, 2**31 - 1), queue])
                if uid:
                    task_uids.append(uid)
                    added = True
                else:
                    continue
            if not added:
                break

        tasks = []
        for task_uid in task_uids:
            task = self.backend.get_task(task_uid)
            if task:
                tasks.append(task)
        return tasks

    def _increment_metrics_by(self, metric: KartonMetrics, identity: str, by: int) -> None:
        self.backend.redis.hincrby(metric.value, identity, by)

    def process(self, *args: Any) -> None:
        """
        This method is defined by Karton, but, as this class runs its task in batches, is not needed.
        We implement it to suppress abstract class instantiation warnings.
        """
        assert False, (
            "process() called. This is a class that allows handling multiple tasks "
            "at once - to use this feature, implement run_multiple()"
        )
