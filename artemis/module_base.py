import datetime
import logging
import random
import sys
import time
import traceback
import urllib.parse
from ipaddress import ip_address
from typing import List, Optional, Tuple

import requests
import timeout_decorator
from karton.core import Karton, Task
from karton.core.backend import KartonMetrics
from karton.core.task import TaskState as KartonTaskState
from redis import Redis

from artemis.binds import TaskStatus, TaskType
from artemis.blocklist import load_blocklist, should_block_scanning
from artemis.config import Config
from artemis.db import DB
from artemis.domains import is_domain
from artemis.redis_cache import RedisCache
from artemis.resolvers import lookup
from artemis.resource_lock import FailedToAcquireLockException, ResourceLock
from artemis.retrying_resolver import setup_retrying_resolver
from artemis.task_utils import (
    get_target_host,
    increase_analysis_num_finished_tasks,
    increase_analysis_num_in_progress_tasks,
)
from artemis.utils import is_ip_address

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

    timeout_seconds = Config.Limits.TASK_TIMEOUT_SECONDS

    lock_target = Config.Locking.LOCK_SCANNED_TARGETS

    # Sometimes there are multiple modules that make use of a resource, e.g. whois database.
    # This is the name of the resource - if a module locks it, no other module using this
    # resource can use it.
    resource_name_to_lock_before_scanning: Optional[str] = None

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self.cache = RedisCache(REDIS, self.identity)
        self.lock = ResourceLock(res_name=self.identity)
        self.taking_tasks_from_queue_lock = ResourceLock(res_name=f"taking-tasks-from-queue-{self.identity}")
        self.redis = REDIS

        if Config.Miscellaneous.BLOCKLIST_FILE:
            self._blocklist = load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE)
        else:
            self._blocklist = []

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

        for handler in self.log.handlers:
            handler.setFormatter(logging.Formatter(Config.Miscellaneous.LOGGING_FORMAT_STRING))

    def cached_get(self, url: str, cache_key: str, timeout: int = 24 * 60 * 60) -> bytes:
        if not self.cache.get(cache_key):
            data = requests.get(url).content
            self.cache.set(cache_key, data, timeout=timeout)
            return data
        else:
            cache_result = self.cache.get(cache_key)
            assert cache_result
            return cache_result

    def add_task(self, current_task: Task, new_task: Task) -> None:
        analysis = self.db.get_analysis_by_id(current_task.root_uid)
        if analysis and analysis.get("stopped", False):
            # Don't add tasks to stopped analyses
            return

        new_task.priority = current_task.priority
        new_task.payload["created_at"] = datetime.datetime.utcnow().isoformat()

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

                num_tasks_done = self._single_iteration()

                task_id += num_tasks_done

                if not num_tasks_done:
                    # Prevent busywaiting causing a large load on Redis, but don't wait if we actually
                    # are consuming tasks.
                    time.sleep(self.task_poll_interval_seconds)

        if task_id >= Config.Miscellaneous.MAX_NUM_TASKS_TO_PROCESS:
            self.log.info("Exiting loop after processing %d tasks", task_id)
        else:
            self.log.info("Exiting loop, shutdown=%s", self.shutdown)

    def _single_iteration(self) -> int:
        self.log.debug("single iteration")
        if self.resource_name_to_lock_before_scanning:
            self.log.debug(f"locking {self.resource_name_to_lock_before_scanning}")
            resource_lock = ResourceLock(
                f"resource-lock-{self.resource_name_to_lock_before_scanning}",
                max_tries=Config.Locking.SCAN_DESTINATION_LOCK_MAX_TRIES,
            )
            try:
                resource_lock.acquire()
                self.log.debug("Succeeded to lock resource %s", self.resource_name_to_lock_before_scanning)
            except FailedToAcquireLockException:
                self.log.debug("Failed to lock resource %s", self.resource_name_to_lock_before_scanning)
                return 0
        else:
            resource_lock = None

        tasks, locks = self._take_and_lock_tasks(self.task_max_batch_size)
        self._log_tasks(tasks)

        for task in tasks:
            increase_analysis_num_in_progress_tasks(REDIS, task.root_uid, by=1)

        self.internal_process_multiple(tasks)

        for task in tasks:
            increase_analysis_num_finished_tasks(REDIS, task.root_uid)
            increase_analysis_num_in_progress_tasks(REDIS, task.root_uid, by=-1)

        for lock in locks:
            if lock:
                lock.release()

        if resource_lock:
            resource_lock.release()

        return len(tasks)

    def _take_and_lock_tasks(self, num_tasks: int) -> Tuple[List[Task], List[Optional[ResourceLock]]]:
        self.log.debug("[taking tasks] Acquiring lock to take tasks from queue")
        try:
            self.taking_tasks_from_queue_lock.acquire()
        except FailedToAcquireLockException:
            self.log.info("[taking tasks] Failed to acquire lock to take tasks from queue")
            return [], []

        try:
            tasks = []
            locks: List[Optional[ResourceLock]] = []
            for queue in self.backend.get_queue_names(self.identity):
                self.log.debug("[taking tasks] Taking tasks from queue {queue}")
                for i, item in enumerate(self.backend.redis.lrange(queue, 0, -1)):
                    task = self.backend.get_task(item)

                    if task is None:
                        self.backend.redis.lrem(queue, 1, item)
                        continue

                    scan_destination = self._get_scan_destination(task)

                    if self.lock_target:
                        lock = ResourceLock(
                            f"lock-{scan_destination}", max_tries=Config.Locking.SCAN_DESTINATION_LOCK_MAX_TRIES
                        )

                        if lock.is_acquired():
                            continue
                        else:
                            try:
                                lock.acquire()
                                tasks.append(task)
                                locks.append(lock)
                                self.log.info(
                                    "[taking tasks] Succeeded to lock task %s (orig_uid=%s destination=%s, %d in queue %s), %d/%d locked",
                                    task.uid,
                                    task.orig_uid,
                                    scan_destination,
                                    i,
                                    queue,
                                    len(tasks),
                                    num_tasks,
                                )
                                self.backend.redis.lrem(queue, 1, item)
                                if len(tasks) >= num_tasks:
                                    break
                            except FailedToAcquireLockException:
                                self.log.warning(
                                    "Failed to lock task %s (orig_uid=%s destination=%s)",
                                    task.uid,
                                    task.orig_uid,
                                    scan_destination,
                                )
                                continue
                    else:
                        tasks.append(task)
                        locks.append(None)
                        self.backend.redis.lrem(queue, 1, item)
                        if len(tasks) >= num_tasks:
                            break
                if len(tasks) >= num_tasks:
                    break
        except Exception:
            for already_acquired_lock in locks:
                if already_acquired_lock:
                    already_acquired_lock.release()
            raise
        finally:
            self.taking_tasks_from_queue_lock.release()

        self.log.debug("[taking tasks] Tasks from queue taken")

        tasks_not_blocklisted = []
        locks_for_tasks_not_blocklisted: List[Optional[ResourceLock]] = []
        for task, lock_for_task in zip(tasks, locks):
            skip = False
            if self._is_blocklisted(task):
                self.log.info("Task %s is blocklisted for module %s", task, self.identity)
                skip = True
            elif self.identity in task.payload_persistent.get("disabled_modules", []):
                self.log.info("Module %s disabled for task %s", self.identity, task)
                skip = True
            if skip:
                increase_analysis_num_finished_tasks(REDIS, task.root_uid)
                self.backend.increment_metrics(KartonMetrics.TASK_CONSUMED, self.identity)
                self.backend.set_task_status(task, KartonTaskState.FINISHED)
                if lock_for_task:
                    lock_for_task.release()
            else:
                tasks_not_blocklisted.append(task)
                locks_for_tasks_not_blocklisted.append(lock_for_task)
        self.log.debug(
            "[taking tasks] Tasks from queue taken and filtered, %d left after filtering", len(tasks_not_blocklisted)
        )
        return tasks_not_blocklisted, locks_for_tasks_not_blocklisted

    def _is_blocklisted(self, task: Task) -> bool:
        if self.identity == "classifier":
            # It's not possible to blocklist classifier, as blocklists block IPs or domains, and classifier supports
            # various input types (e.g. IP ranges, converting them to IPs).
            return False

        host = get_target_host(task)

        if is_domain(host):
            try:
                ip_addresses = list(lookup(host))
            except Exception:
                self.log.error(f"Exception while trying to obtain IP for host {host}")
                ip_addresses = []

            if ip_addresses:
                for ip in ip_addresses:
                    if should_block_scanning(domain=host, ip=ip, karton_name=self.identity, blocklist=self._blocklist):
                        return True
            else:
                if should_block_scanning(domain=host, ip=None, karton_name=self.identity, blocklist=self._blocklist):
                    return True
        elif is_ip_address(host):
            domain = task.payload.get("last_domain", None)
            if should_block_scanning(domain=domain, ip=host, karton_name=self.identity, blocklist=self._blocklist):
                return True
        else:
            assert False, f"expected {host} to be either domain or an IP address"
        return False

    def run(self, current_task: Task) -> None:
        raise NotImplementedError()

    def run_multiple(self, tasks: List[Task]) -> None:
        raise NotImplementedError()

    def internal_process_multiple(self, tasks: List[Task]) -> None:
        if not tasks:
            return

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
                timeout_decorator.timeout(self.timeout_seconds)(lambda: self.run_multiple(tasks))()
            else:
                (task,) = tasks
                timeout_decorator.timeout(self.timeout_seconds)(lambda: self.run(task))()
        except Exception:
            for task in tasks:
                self.db.save_task_result(task=task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise

    def _log_tasks(self, tasks: List[Task]) -> None:
        if not tasks:
            return

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
        cache_key = "scan-destination-" + task.uid
        cached_destination = self.cache.get(cache_key)
        if cached_destination:
            return cached_destination.decode("ascii")

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
        elif task.headers["type"] == TaskType.DEVICE:
            try:
                result = self._get_ip_for_locking(task.payload["host"])
            except UnknownIPException:
                result = task.payload["host"]

        assert isinstance(result, str)
        self.cache.set(cache_key, result.encode("ascii"))
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
            ip_addresses = list(lookup(host))
        except Exception as e:
            raise UnknownIPException(f"Exception while trying to obtain IP for host {host}", e)

        if not ip_addresses:
            raise UnknownIPException(f"Unknown IP for host {host}")

        return random.choice(ip_addresses)
