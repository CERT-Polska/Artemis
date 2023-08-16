import random
import time
import traceback
import urllib.parse
from abc import abstractmethod
from ipaddress import ip_address
from typing import Optional

import requests
import timeout_decorator
from karton.core import Karton, Task
from karton.core.task import TaskState as KartonTaskState
from redis import Redis

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.db import DB
from artemis.redis_cache import RedisCache
from artemis.resolvers import ip_lookup
from artemis.resource_lock import FailedToAcquireLockException, ResourceLock

REDIS = Redis.from_url(Config.Data.REDIS_CONN_STR)


class UnknownIPException(Exception):
    pass


class ArtemisBase(Karton):
    """
    Artemis base module. Provides helpers (such as e.g. cache) for all modules.
    """

    task_poll_interval_seconds = 2

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

        task_id = 0
        with self.graceful_killer():
            while not self.shutdown and task_id < Config.Miscellaneous.MAX_NUM_TASKS_TO_PROCESS:
                if self.backend.get_bind(self.identity) != self._bind:
                    self.log.info("Binds changed, shutting down.")
                    break

                time.sleep(self.task_poll_interval_seconds)
                task = self._consume_random_routed_task(self.identity)
                if task:
                    task_id += 1

                    self.internal_process(task)
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

    @abstractmethod
    def run(self, current_task: Task) -> None:
        raise NotImplementedError()

    def internal_process(self, current_task: Task) -> None:
        scan_destination = self._get_scan_destination(current_task)

        if self.lock_target:
            try:
                with ResourceLock(
                    REDIS, f"lock-{scan_destination}", max_tries=Config.Locking.SCAN_DESTINATION_LOCK_MAX_TRIES
                ):
                    self.log.info(
                        "Succeeded to lock task %s (orig_uid=%s destination=%s)",
                        current_task.uid,
                        current_task.orig_uid,
                        scan_destination,
                    )

                    self._log_task(current_task)
                    super().internal_process(current_task)
            except FailedToAcquireLockException:
                self.log.info(
                    "Rescheduling task %s for later (orig_uid=%s destination=%s) because other module is currently scanning the same IP. We will attempt the task later.",
                    current_task.uid,
                    current_task.orig_uid,
                    scan_destination,
                )
                self.reschedule_task(current_task)
                return
        else:
            self._log_task(current_task)
            super().internal_process(current_task)

    def process(self, current_task: Task) -> None:
        try:
            timeout_decorator.timeout(Config.Limits.TASK_TIMEOUT_SECONDS)(lambda: self.run(current_task))()
        except Exception:
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise

    def _log_task(self, current_task: Task) -> None:
        self.log.info(
            "Processing task %s (headers=%s payload=%s payload_persistent=%s priority=%s)",
            current_task.uid,
            repr(current_task.headers),
            repr(current_task.payload),
            repr(current_task.payload_persistent),
            current_task.priority.value,
        )

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
