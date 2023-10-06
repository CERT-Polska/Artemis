import random
import sys
import time
import traceback
import urllib.parse
from ipaddress import ip_address
from typing import List, Optional

import requests
import timeout_decorator
from karton.core import Karton, Task
from karton.core.backend import KartonMetrics
from karton.core.task import TaskState as KartonTaskState
from redis import Redis

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.db import DB
from artemis.redis_cache import RedisCache
from artemis.resolvers import ip_lookup
from artemis.resource_lock import FailedToAcquireLockException, ResourceLock
from artemis.retrying_resolver import setup_retrying_resolver

REDIS = Redis.from_url(Config.Data.REDIS_CONN_STR)

setup_retrying_resolver()


class UnknownIPException(Exception):
    pass


class ArtemisBase(Karton):
    """
    Artemis base module. Provides helpers (such as e.g. cache) for all modules.
    """

    task_poll_interval_seconds = 2
    batch_tasks = False
    # This is the maximum batch size. Due to the fact that we may be unable to lock some targets because
    # their IPs are already scanned, the actual batch size may be lower.
    task_max_batch_size = 1

    lock_target = Config.Locking.LOCK_SCANNED_TARGETS

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self.cache = RedisCache(REDIS, self.identity)
        self.lock = ResourceLock(redis=REDIS, res_name=self.identity)
        self.redis = REDIS

        if db:
            self.db = db
        else:
            self.db = DB()

        if self.batch_tasks:
            assert (
                self.task_max_batch_size > 1
            ), "If batch_tasks is enabled, task_max_batch_size must be greater than 1."
        else:
            assert (
                self.task_max_batch_size == 1
            ), "If batch_tasks is disabled, task_max_batch_size makes no sense to be other than 1."

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

    def cached_get(self, url: str, cache_key: str) -> bytes:
        if not self.cache.get(cache_key):
            data = requests.get(url).content
            self.cache.set(cache_key, data)
            return data
        else:
            cache_result = self.cache.get(cache_key)
            assert cache_result
            return cache_result

    def add_task(self, current_task: Task, new_task: Task) -> None:
        new_task.set_task_parent(current_task)
        new_task.merge_persistent_payload(current_task)

        if "domain" in new_task.payload:
            new_task.payload["last_domain"] = new_task.payload["domain"]
        elif "domain" in current_task.payload:
            new_task.payload["last_domain"] = current_task.payload["domain"]
        elif "last_domain" in current_task.payload:
            new_task.payload["last_domain"] = current_task.payload["last_domain"]

        if self.db.save_scheduled_task(new_task):
            self.log.info("Task is a new task, adding: %s", new_task)
            self.send_task(new_task)
        else:
            self.log.info("Task is not a new task, not adding: %s", new_task)

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

        task_id = 0
        with self.graceful_killer():
            while not self.shutdown and task_id < Config.Miscellaneous.MAX_NUM_TASKS_TO_PROCESS:
                if self.backend.get_bind(self.identity) != self._bind:
                    self.log.info("Binds changed, shutting down.")
                    break

                time.sleep(self.task_poll_interval_seconds)
                tasks = []
                for _ in range(self.task_max_batch_size):
                    task = self._consume_random_routed_task(self.identity)
                    if task:
                        if self.identity in task.payload_persistent.get("disabled_modules", []):
                            self.log.info("Module %s disabled for task %s", self.identity, task)
                            self.backend.increment_metrics(KartonMetrics.TASK_CONSUMED, self.identity)
                            self.backend.set_task_status(task, KartonTaskState.FINISHED)
                        else:
                            tasks.append(task)

                if len(tasks) > 0:
                    task_id += len(tasks)

                    self.lock_and_internal_process_multiple(tasks)

        if task_id >= Config.Miscellaneous.MAX_NUM_TASKS_TO_PROCESS:
            self.log.info("Exiting loop after processing %d tasks", task_id)
        else:
            self.log.info("Exiting loop, shutdown=%s", self.shutdown)

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
        task.status = KartonTaskState.SPAWNED
        self.backend.produce_routed_task(self.identity, task)

    def run(self, current_task: Task) -> None:
        raise NotImplementedError()

    def run_multiple(self, tasks: List[Task]) -> None:
        raise NotImplementedError()

    def lock_and_internal_process_multiple(self, tasks: List[Task]) -> None:
        if self.lock_target:
            locks_acquired = []
            tasks_to_reschedule = []
            tasks_locked = []
            for task in tasks:
                scan_destination = self._get_scan_destination(task)

                lock = ResourceLock(
                    REDIS, f"lock-{scan_destination}", max_tries=Config.Locking.SCAN_DESTINATION_LOCK_MAX_TRIES
                )

                try:
                    lock.acquire()
                    locks_acquired.append(lock)
                    tasks_locked.append(task)
                    self.log.info(
                        "Succeeded to lock task %s (orig_uid=%s destination=%s)",
                        task.uid,
                        task.orig_uid,
                        scan_destination,
                    )
                except FailedToAcquireLockException:
                    self.log.warning(
                        "Failed to lock task %s (orig_uid=%s destination=%s)",
                        task.uid,
                        task.orig_uid,
                        scan_destination,
                    )
                    tasks_to_reschedule.append(task)

            self.log.info(
                "Out of %s tasks we successfully locked %s.",
                len(tasks),
                len(locks_acquired),
            )

            for task_to_reschedule in tasks_to_reschedule:
                self.reschedule_task(task_to_reschedule)

            if len(tasks_to_reschedule):
                self.log.info(
                    "Rescheduled %s tasks because other module is currently scanning the same IP. We will attempt the tasks later.",
                    len(tasks_to_reschedule),
                )

            self._log_tasks(tasks_locked)
            self.internal_process_multiple(tasks_locked)

            for lock in locks_acquired:
                lock.release()
        else:
            self._log_tasks(tasks)
            self.internal_process_multiple(tasks)

    def internal_process_multiple(self, tasks: List[Task]) -> None:
        tasks_filtered = []
        for task in tasks:
            if task.matches_filters(self.filters):
                tasks_filtered.append(task)
            else:
                self.log.info("Task rejected because binds are no longer valid.")
                self.backend.set_task_status(task, KartonTaskState.FINISHED)

        exception_str = None

        try:
            self.log.info(
                "Received %s new tasks - %s", len(tasks_filtered), ", ".join([task.uid for task in tasks_filtered])
            )
            for task in tasks_filtered:
                self.backend.set_task_status(task, KartonTaskState.STARTED)

            self._run_pre_hooks()

            saved_exception = None
            try:
                self.process_multiple(tasks_filtered)
            except Exception as exc:
                saved_exception = exc
                raise
            finally:
                self._run_post_hooks(saved_exception)

            self.log.info("%s tasks done - %s", len(tasks_filtered), ", ".join([task.uid for task in tasks_filtered]))
        except Exception:
            exc_info = sys.exc_info()
            exception_str = traceback.format_exception(*exc_info)

            for _ in tasks_filtered:
                self.backend.increment_metrics(KartonMetrics.TASK_CRASHED, self.identity)
            self.log.exception(
                "Failed to process %s tasks - %s", len(tasks_filtered), ", ".join([task.uid for task in tasks_filtered])
            )
        finally:
            for task in tasks_filtered:
                self.backend.increment_metrics(KartonMetrics.TASK_CONSUMED, self.identity)

                task_state = KartonTaskState.FINISHED

                # report the task status as crashed
                # if an exception was caught while processing
                if exception_str is not None:
                    task_state = KartonTaskState.CRASHED
                    task.error = exception_str

                self.backend.set_task_status(task, task_state)

    def process(self, task: Task) -> None:
        self.process_multiple([task])

    def process_multiple(self, tasks: List[Task]) -> None:
        if len(tasks) == 0:
            return

        try:
            if self.batch_tasks:
                timeout_decorator.timeout(Config.Limits.TASK_TIMEOUT_SECONDS)(lambda: self.run_multiple(tasks))()
            else:
                (task,) = tasks
                timeout_decorator.timeout(Config.Limits.TASK_TIMEOUT_SECONDS)(lambda: self.run(task))()
        except Exception:
            for task in tasks:
                self.db.save_task_result(task=task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise

    def _log_tasks(self, tasks: List[Task]) -> None:
        message = "Processing %d tasks: " % len(tasks)
        for i, task in enumerate(tasks):
            message += "%s (headers=%s payload=%s payload_persistent=%s priority=%s)" % (
                task.uid,
                repr(task.headers),
                repr(task.payload),
                repr(task.payload_persistent),
                task.priority.value,
            )

            if i < len(tasks) - 1:
                message += ", "
        self.log.info(message)

    def _get_scan_destination(self, task: Task) -> str:
        result = None
        if task.headers["type"] == TaskType.NEW:
            result = task.payload["data"]
        elif task.headers["type"] == TaskType.IP:
            result = task.payload["ip"]
        elif task.headers["type"] == TaskType.DOMAIN:
            # This is an approximation. Sometimes, when we scan domain, we actually scan the IP the domain
            # resolves to (e.g. in port_scan karton), sometimes the domain itself (e.g. the DNS kartons) or
            # even the MX servers. Therefore this will not map 1:1 to the actual host being scanned.
            try:
                result = self._get_ip_for_locking(task.payload["domain"])
            except UnknownIPException:
                result = task.payload["domain"]
        elif task.headers["type"] == TaskType.WEBAPP:
            host = urllib.parse.urlparse(task.payload["url"]).hostname
            try:
                result = self._get_ip_for_locking(host)
            except UnknownIPException:
                result = host
        elif task.headers["type"] == TaskType.URL:
            host = urllib.parse.urlparse(task.payload["url"]).hostname
            try:
                result = self._get_ip_for_locking(host)
            except UnknownIPException:
                result = host
        elif task.headers["type"] == TaskType.SERVICE:
            try:
                result = self._get_ip_for_locking(task.payload["host"])
            except UnknownIPException:
                result = task.payload["host"]

        assert isinstance(result, str)
        return result

    def _get_ip_for_locking(self, host: str) -> str:
        try:
            # if this doesn't throw then we have an IP address
            ip_address(host)
            return host
        except ValueError:
            pass

        # Here, we use the the DoH resolvers so that we don't leak information if using proxies.
        # There is a chance that the IP returned here (chosen randomly from a set of IP adresses)
        # would be different from the one chosen for the actual connection - but we hope that over
        # time and across multiple scanner instances the overall load would be approximately similar
        # to one request per Config.Limits.SECONDS_PER_REQUEST.
        try:
            ip_addresses = list(ip_lookup(host))
        except Exception as e:
            raise UnknownIPException(f"Exception while trying to obtain IP for host {host}", e)

        if not ip_addresses:
            raise UnknownIPException(f"Unknown IP for host {host}")

        return random.choice(ip_addresses)
