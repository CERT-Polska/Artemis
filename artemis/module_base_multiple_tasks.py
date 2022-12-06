import abc
import sys
import time
import traceback
from typing import Any, List, cast

from karton.core import Task
from karton.core.backend import KartonMetrics
from karton.core.task import TaskState

from artemis.binds import TaskStatus
from artemis.module_base import ArtemisBase


class ArtemisMultipleTasksBase(ArtemisBase):
    seconds_between_task_list_polling = 10
    batch_size = 50

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
                    self.internal_process_multiple(tasks)
                else:
                    time.sleep(self.seconds_between_task_list_polling)
        except KeyboardInterrupt as e:
            self.log.info("Hard shutting down!")
            raise e

    def internal_process_multiple(self, tasks: List[Task]) -> None:
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
                self.process_multiple(tasks)
            except Exception as exc:
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

    def process_multiple(self, task_dicts: List[Any]) -> None:
        tasks = [cast(Task, task_dict) for task_dict in task_dicts]
        try:
            self.run_multiple(tasks)
        except Exception:
            for task in tasks:
                self.db.save_task_result(task=task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise

    def _consume_routed_tasks(self, identity: str, max_count: int) -> List[Task]:
        task_uids: List[str] = []
        for queue in self.backend.get_queue_names(identity):
            task_uids.extend(
                self.backend.consume_queues_batch(
                    queue,
                    max_count=max_count - len(task_uids),
                )
            )
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
        assert(False, "process called instead of process_multiple")
