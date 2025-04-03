import datetime
import fcntl
import json
import logging
import random
import shutil
import sys
import time
import traceback
import urllib.parse
from ipaddress import ip_address
from typing import Any, Callable, Dict, List, Optional, Tuple

import timeout_decorator
from karton.core import Karton, Task
from karton.core.backend import KartonMetrics
from karton.core.task import TaskState as KartonTaskState
from redis import Redis
from requests.exceptions import RequestException

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.blocklist import load_blocklist, should_block_scanning
from artemis.config import Config
from artemis.db import DB
from artemis.domains import is_domain
from artemis.ip_utils import is_ip_address
from artemis.output_redirector import OutputRedirector
from artemis.placeholder_page_detector import PlaceholderPageDetector
from artemis.redis_cache import RedisCache
from artemis.resolvers import NoAnswer, ResolutionException, lookup
from artemis.resource_lock import FailedToAcquireLockException, ResourceLock
from artemis.retrying_resolver import setup_retrying_resolver
from artemis.task_utils import (
    get_target_host,
    get_target_url,
    increase_analysis_num_finished_tasks,
    increase_analysis_num_in_progress_tasks,
)
from artemis.utils import throttle_request

REDIS = Redis.from_url(Config.Data.REDIS_CONN_STR)

setup_retrying_resolver()


class UnknownIPException(Exception):
    pass


class ArtemisBase(Karton):
    """
    Artemis base module. Provides helpers (such as e.g. cache) for all modules.
    """

    task_poll_interval_seconds = 10
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

    # Enabled only if LOCK_SCANNED_TARGETS is enabled.
    # Sometimes the task queue is very long and e.g. the first n tasks can't be taken because they concern IPs that
    # are already scanned. To make scanning faster, Artemis remembers the position in the task queue for the next
    # QUEUE_LOCATION_MAX_AGE_SECONDS in order not to repeat trying to lock the first tasks in the queue.
    queue_location_max_age_seconds: int = Config.Locking.QUEUE_LOCATION_MAX_AGE_SECONDS

    requests_per_second_for_current_tasks: float = Config.Limits.REQUESTS_PER_SECOND

    # Sometimes a module needs to make a large number of HTTP requests and a small number of failures is OK.
    # These two counters control that. To use the feature use self.forgiving_http_get or self.forgiving_http_post
    _forgiven_http_requests: int = 0
    _forgiven_http_requests_max: int = 10

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self.cache = RedisCache(REDIS, self.identity)
        self.lock = ResourceLock(res_name=self.identity)
        self.setup_logger(Config.Miscellaneous.LOG_LEVEL)
        self.taking_tasks_from_queue_lock = ResourceLock(res_name=f"taking-tasks-from-queue-{self.identity}")
        self.redis = REDIS

        if Config.Miscellaneous.ADDITIONAL_HOSTS_FILE_PATH:
            with open(Config.Miscellaneous.ADDITIONAL_HOSTS_FILE_PATH, "r") as additional_data_file:
                with open("/etc/hosts", "a") as hosts_file:
                    fcntl.flock(hosts_file.fileno(), fcntl.LOCK_EX)
                    hosts_file.write(additional_data_file.read())
                    fcntl.flock(hosts_file.fileno(), fcntl.LOCK_UN)

        if Config.Limits.SCAN_SPEED_OVERRIDES_FILE:
            with open(Config.Limits.SCAN_SPEED_OVERRIDES_FILE, "r") as f:
                self._scan_speed_overrides: Dict[str, float] = json.load(f)
        else:
            self._scan_speed_overrides = {}

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

    def add_task_if_domain_exists(self, current_task: Task, new_task: Task) -> bool:
        """
        Add a new task if the domain in the task payload exists.

        Args:
            current_task (Task): The current task being processed.
            new_task (Task): The new task to potentially add.

        Returns True if the task was actually added.
        """
        domain = new_task.payload.get("domain")
        if not domain:
            self.log.info("No domain found in new task payload - adding it, as it might be an IP task")
            self.add_task(current_task, new_task)
            return True

        if self.check_domain_exists_or_is_placeholder(domain):
            self.add_task(current_task, new_task)
            return True
        else:
            self.log.info("Skipping invalid domain (nonexistent/placeholder): %s", domain)
            return False

    def check_domain_exists_or_is_placeholder(self, domain: str) -> bool:
        """
        Check if a domain exists or is a placeholder page.

        Args:
            domain (str): The domain to check.

        Returns:
            bool: True if the domain exists and is not a placeholder page, False otherwise.
        """
        if Config.Modules.PlaceholderPageContent.ENABLE_PLACEHOLDER_PAGE_DETECTOR:
            placeholder_page = PlaceholderPageDetector()
            if placeholder_page.is_placeholder(domain):
                return False

        return self.check_domain_exists(domain)

    def check_domain_exists(self, domain: str) -> bool:
        """
        Check if a domain exists by looking up its DNS records.

        Args:
            domain (str): The domain to check.

        Returns:
            bool: True if the domain exists, False otherwise.
        """
        try:
            # Don't check NS, as a domain that has only NS is not worth scanning
            for record_type in ["A", "AAAA", "MX"]:
                try:
                    records = lookup(domain, record_type)
                    if records:
                        return True
                except NoAnswer:
                    pass

            return False

        except ResolutionException:
            return False

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

        _, _, free_disk_space = shutil.disk_usage("/")
        if free_disk_space < 1024 * 1024 * Config.Miscellaneous.STOP_SCANNING_MODULES_IF_FREE_DISK_SPACE_LOWER_THAN_MB:
            self.log.error(
                "Stopping scanning as disk space is lower than %s MB (it's %s MB)",
                Config.Miscellaneous.STOP_SCANNING_MODULES_IF_FREE_DISK_SPACE_LOWER_THAN_MB,
                free_disk_space / (1024 * 1024),
            )
            self._shutdown = True
            return 0

        # In case there was a problem and previous locks was not released
        ResourceLock.release_all_locks(self.log)

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

        tasks, locks, num_task_removed_from_queue = self._take_and_lock_tasks(self.task_max_batch_size)
        self._log_tasks(tasks)

        for task in tasks:
            increase_analysis_num_in_progress_tasks(REDIS, task.root_uid, by=1)

        requests_per_second_overrides = [
            task.payload_persistent.get("requests_per_second_override")
            for task in tasks
            if "requests_per_second_override" in task.payload_persistent
        ]

        for task in tasks:
            destination = self._get_scan_destination(task)
            if destination in self._scan_speed_overrides:
                requests_per_second_overrides.append(self._scan_speed_overrides[destination])

        self.requests_per_second_for_current_tasks = min(  # type: ignore
            requests_per_second_overrides if requests_per_second_overrides else [Config.Limits.REQUESTS_PER_SECOND]
        )

        if requests_per_second_overrides:
            self.log.info("Setting requests per second to %f", self.requests_per_second_for_current_tasks)

        if len(tasks):
            time_start = time.time()
            self.internal_process_multiple(tasks)
            self.log.info(
                "Took %.02fs to perform %d tasks by module %s",
                time.time() - time_start,
                len(tasks),
                self.identity,
            )

        for task in tasks:
            increase_analysis_num_finished_tasks(REDIS, task.root_uid)
            increase_analysis_num_in_progress_tasks(REDIS, task.root_uid, by=-1)

        for lock in locks:
            if lock:
                lock.release()

        if resource_lock:
            resource_lock.release()

        return num_task_removed_from_queue

    def _take_and_lock_tasks(self, num_tasks: int) -> Tuple[List[Task], List[Optional[ResourceLock]], int]:
        self.log.debug("[taking tasks] Acquiring lock to take tasks from queue")
        try:
            self.taking_tasks_from_queue_lock.acquire()
        except FailedToAcquireLockException:
            self.log.info("[taking tasks] Failed to acquire lock to take tasks from queue")
            return [], [], 0

        try:
            tasks = []
            locks: List[Optional[ResourceLock]] = []

            if (
                float(REDIS.get(f"queue_location_timestamp-{self.identity}") or 0)
                < time.time() - self.queue_location_max_age_seconds
            ):
                REDIS.set(f"queue_id-{self.identity}", 0)
                REDIS.set(f"queue_position-{self.identity}", 0)
                REDIS.set(f"queue_location_timestamp-{self.identity}", time.time())

            queue_id = int(REDIS.get(f"queue_id-{self.identity}") or 0)

            for i, queue in list(enumerate(self.backend.get_queue_names(self.identity)))[queue_id:]:
                if i > queue_id:
                    REDIS.set(f"queue_position-{self.identity}", 0)

                original_queue_position = int(REDIS.get(f"queue_position-{self.identity}") or 0)
                self.log.debug(f"[taking tasks] Taking tasks from queue {queue} from task {original_queue_position}")
                if self.lock_target:
                    REDIS.set(f"queue_id-{self.identity}", i)
                for i_from_queue_position, item in enumerate(
                    self.backend.redis.lrange(queue, original_queue_position, -1)
                ):
                    i = i_from_queue_position + original_queue_position

                    if self.lock_target:
                        REDIS.set(f"queue_position-{self.identity}", i)

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
                self.log.debug(f"[taking tasks] {len(tasks)} tasks after checking queue {queue}")
                if len(tasks) >= num_tasks:
                    break

            if len(tasks) < num_tasks:
                REDIS.set(f"queue_id-{self.identity}", 0)
                REDIS.set(f"queue_position-{self.identity}", 0)
                REDIS.set(f"queue_location_timestamp-{self.identity}", time.time())
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
            elif self.identity in task.payload_persistent.get("disabled_modules", "").split(","):
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
        return tasks_not_blocklisted, locks_for_tasks_not_blocklisted, len(tasks)

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

        self._forgiven_http_requests = 0
        output_redirector = OutputRedirector()

        tasks_filtered = []
        for task in tasks:
            should_check_connection = False
            if task.headers["type"] == TaskType.SERVICE and task.headers["service"] == Service.HTTP:
                should_check_connection = True
            elif task.headers["type"] == TaskType.WEBAPP:
                should_check_connection = True
            elif task.headers["type"] == TaskType.URL:
                should_check_connection = True

            if not should_check_connection or self.check_connection_to_base_url_and_save_error(task):
                tasks_filtered.append(task)

        tasks = tasks_filtered
        if not tasks:
            return

        try:
            with output_redirector:
                if self.batch_tasks:
                    timeout_decorator.timeout(self.timeout_seconds)(lambda: self.run_multiple(tasks))()
                else:
                    (task,) = tasks
                    timeout_decorator.timeout(self.timeout_seconds)(lambda: self.run(task))()
        except Exception:
            for task in tasks:
                self.db.save_task_result(task=task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise
        finally:
            for task in tasks:
                self.db.save_task_logs(task.uid, output_redirector.get_output())

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
            return cached_destination.decode("utf-8")

        result = None
        if task.headers["type"] == TaskType.NEW:
            result = task.payload["data"]
        elif task.headers["type"] == TaskType.IP:
            result = task.payload["ip"]
        elif task.headers["type"] == TaskType.DOMAIN or task.headers["type"] == TaskType.DOMAIN_THAT_MAY_NOT_EXIST:
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
        self.cache.set(cache_key, result.encode("utf-8"))
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
        # to Config.Limits.REQUESTS_PER_SECOND requests per second.
        try:
            ip_addresses = list(lookup(host))
        except Exception as e:
            raise UnknownIPException(f"Exception while trying to obtain IP for host {host}", e)

        if not ip_addresses:
            raise UnknownIPException(f"Unknown IP for host {host}")

        return random.choice(ip_addresses)

    def check_connection_to_base_url_and_save_error(self, task: Task) -> bool:
        base_url = get_target_url(task)
        scan_destination = self._get_scan_destination(task)
        lock = ResourceLock(f"lock-{scan_destination}", max_tries=Config.Locking.SCAN_DESTINATION_LOCK_MAX_TRIES)

        try:
            response = self.http_get(base_url)
            if any(
                [
                    message in response.content
                    for message in [
                        "Cloudflare</title>",
                        "<hr><center>cloudflare</center>",
                        "Incapsula incident ID",
                        'script src="/_Incapsula_Resource',
                        "Please wait while your request is being verified...",
                        "<title>Unauthorized Access</title>",
                        "<title>Attack Detected</title>",
                        "<h1>You have been blocked</h1></html>",
                    ]
                ]
            ):
                self.db.save_task_result(
                    task=task,
                    status=TaskStatus.ERROR,
                    status_reason=f"Unable to connect to base URL: {base_url}: WAF detected, task skipped",
                    data={"waf_detected": True},
                )
                self.log.info(
                    f"Unable to connect to base URL: {base_url}: WAF detected, task skipped, releasing lock for {scan_destination}"
                )
                lock.release()
                return False

            return True
        except RequestException as e:
            self.db.save_task_result(
                task=task,
                status=TaskStatus.ERROR,
                status_reason=f"Unable to connect to base URL {base_url}: {repr(e)}, task skipped",
            )
            self.log.info(
                f"Unable to connect to base URL: {base_url}: {repr(e)}, task skipped, releasing lock for {scan_destination}"
            )
            lock.release()
            return False

    def http_get(self, *args, **kwargs) -> http_requests.HTTPResponse:  # type: ignore
        return self._http_request("get", *args, **kwargs)

    def http_post(self, *args, **kwargs) -> http_requests.HTTPResponse:  # type: ignore
        return self._http_request("post", *args, **kwargs)

    # Sometimes a module needs to make a large number of HTTP requests and a small number of failures is OK.
    # These two methods allow to do that.
    def forgiving_http_get(self, *args, **kwargs) -> Optional[http_requests.HTTPResponse]:  # type: ignore
        return self._forgiving_http_request("get", *args, **kwargs)

    def forgiving_http_post(self, *args, **kwargs) -> Optional[http_requests.HTTPResponse]:  # type: ignore
        return self._forgiving_http_request("post", *args, **kwargs)

    def _forgiving_http_request(self, method: str, *args, **kwargs) -> Optional[http_requests.HTTPResponse]:  # type: ignore
        try:
            return self._http_request(method, *args, **kwargs)
        except Exception:
            self._forgiven_http_requests += 1
            if self._forgiven_http_requests > self._forgiven_http_requests_max:
                raise

    def _http_request(self, method: str, *args, **kwargs) -> http_requests.HTTPResponse:  # type: ignore
        kwargs["requests_per_second"] = self.requests_per_second_for_current_tasks
        return getattr(http_requests, method)(*args, **kwargs)  # type: ignore

    def throttle_request(self, f: Callable[[], Any]) -> Any:
        return throttle_request(f, requests_per_second=self.requests_per_second_for_current_tasks)
