import random
import time
import traceback
from abc import abstractmethod
from typing import Optional

import timeout_decorator
from karton.core import Karton, Task

from artemis.binds import TaskStatus
from artemis.config import Config
from artemis.db import DB
from artemis.redis_cache import RedisCache
from artemis.resource_lock import ResourceLock, RescheduleException


class ArtemisBase(Karton):
    """
    Artemis base module. Provides helpers (such as e.g. cache) for all modules.
    """

    TASK_POLL_INTERVAL_SECONDS = 2

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self.cache = RedisCache(Config.REDIS, self.identity)
        self.lock = ResourceLock(redis=Config.REDIS, res_name=self.identity)
        if db:
            self.db = db
        else:
            self.db = DB()

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

    def add_task(self, current_task: Task, new_task: Task) -> None:
        new_task.root_uid = current_task.root_uid
        if self.db.save_scheduled_task(new_task):
            self.send_task(new_task)

    def loop(self) -> None:
        """
        Differs from the original karton implementation: consumes the tasks in random order, so that
        there is lower chance that multiple tasks associated with the same IP (e.g. coming from subdomain
        enumeration) will be taken by multiple threads, thus slowing down the process, as requests for
        the same IP are throttled.
        """
        self.log.info("Service %s started", self.identity)

        # Get the old binds and set the new ones atomically
        old_bind = self.backend.register_bind(self._bind)

        if not old_bind:
            self.log.info("Service binds created.")
        elif old_bind != self._bind:
            self.log.info("Binds changed, old service instances should exit soon.")

        for task_filter in self.filters:
            self.log.info("Binding on: %s", task_filter)

        with self.graceful_killer():
            while not self.shutdown:
                if self.backend.get_bind(self.identity) != self._bind:
                    self.log.info("Binds changed, shutting down.")
                    break

                task = self._consume_random_routed_task(self.identity)
                if task:
                    self.internal_process(task)
                else:
                    time.sleep(self.TASK_POLL_INTERVAL_SECONDS)

    def _consume_random_routed_task(self, identity: str) -> Optional[Task]:
        uid = None
        for queue in self.backend.get_queue_names(identity):
            uid = self._get_random_queue_element(args=[random.randint(0, 2**31 - 1), queue])
            if uid:
                break

        if uid:
            task = self.backend.get_task(uid)
            if task:
                return task
        return None

    def reschedule_task(self, task: Task) -> None:
        """
        Puts task back into the queue.
        Used when performing task requires taking a lock, which is already taken by a long running task.
        In that case, we "reschedule" task for later execution to not block the karton instance.
        This saves task into the DB.
        """
        new_task = Task(
                headers=task.headers,
                payload=task.payload,
                payload_persistent=task.payload_persistent,
                priority=task.priority,
                parent_uid=task.parent)
        # this doesn't need to use self.add_task
        if self.db.save_scheduled_task(new_task):
            self.send_task(new_task)

        self.db.save_task_result(task=current_task, status=TaskStatus.RESCHEDULED, data=traceback.format_exc())

    @abstractmethod
    def run(self, current_task: Task) -> None:
        raise NotImplementedError()

    def process(self, current_task: Task) -> None:
        try:
            timeout_decorator.timeout(Config.TASK_TIMEOUT_SECONDS)(lambda: self.run(current_task))()
        except RescheduleException:
            self.reschedule_task(current_task)
        except Exception:
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise
