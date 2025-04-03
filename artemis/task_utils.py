import urllib
from typing import List

from karton.core import Task
from redis import Redis

from artemis.binds import Service, TaskType
from artemis.ip_utils import to_ip_range


def get_target_host(task: Task) -> str:
    task_type = task.headers["type"]

    if task_type == TaskType.SERVICE:
        payload = task.get_payload("host")
        assert isinstance(payload, str)
        return payload

    if task_type == TaskType.DOMAIN or task_type == TaskType.DOMAIN_THAT_MAY_NOT_EXIST:
        payload = task.get_payload(TaskType.DOMAIN)
        assert isinstance(payload, str)
        return payload

    if task_type == TaskType.IP:
        payload = task.get_payload(TaskType.IP)
        assert isinstance(payload, str)
        return payload

    if task_type == TaskType.WEBAPP or task_type == TaskType.URL:
        url = task.get_payload("url")
        hostname = urllib.parse.urlparse(url).hostname
        assert isinstance(hostname, str)
        return hostname

    if task_type == TaskType.NEW:
        payload = task.get_payload("data")
        assert isinstance(payload, str)

        if ":" in payload:  # host:port
            return payload.split(":")[0]
        return payload

    if task_type == TaskType.DEVICE:
        payload = task.get_payload("host")
        assert isinstance(payload, str)
        return payload

    raise ValueError(f"Unknown target found: {task_type}")


def get_target_url(task: Task) -> str:
    url = task.get_payload("url")

    if url:
        assert isinstance(url, str)
        return url

    if task.headers["service"] != Service.HTTP:
        raise NotImplementedError

    target = get_target_host(task)
    port = task.get_payload("port")
    protocol = "http"
    if task.get_payload("ssl"):
        protocol += "s"

    return f"{protocol}://{target}:{port}"


ANALYSIS_NUM_FINISHED_TASKS_KEY_PREFIX = b"analysis-num-finished-tasks-"
ANALYSIS_NUM_IN_PROGRESS_TASKS_KEY_PREFIX = b"analysis-num-in-progress-tasks-"


def increase_analysis_num_finished_tasks(redis: Redis, root_uid: str, by: int = 1) -> None:  # type: ignore[type-arg]
    redis.incrby(ANALYSIS_NUM_FINISHED_TASKS_KEY_PREFIX + root_uid.encode("ascii"), by)


def get_analysis_num_finished_tasks(redis: Redis, root_uid: str) -> int:  # type: ignore[type-arg]
    return int(redis.get(ANALYSIS_NUM_FINISHED_TASKS_KEY_PREFIX + root_uid.encode("ascii")) or 0)


def increase_analysis_num_in_progress_tasks(redis: Redis, root_uid: str, by: int = 1) -> None:  # type: ignore[type-arg]
    redis.incrby(ANALYSIS_NUM_IN_PROGRESS_TASKS_KEY_PREFIX + root_uid.encode("ascii"), by)


def get_analysis_num_in_progress_tasks(redis: Redis, root_uid: str) -> int:  # type: ignore[type-arg]
    return int(redis.get(ANALYSIS_NUM_IN_PROGRESS_TASKS_KEY_PREFIX + root_uid.encode("ascii")) or 0)


def get_task_target(task: Task) -> str:
    result = None
    if task.headers["type"] == TaskType.NEW:
        result = task.payload.get("data", None)
    elif task.headers["type"] == TaskType.IP:
        result = task.payload.get("ip", None)
    elif task.headers["type"] == TaskType.DOMAIN or task.headers["type"] == TaskType.DOMAIN_THAT_MAY_NOT_EXIST:
        result = task.payload.get("domain", None)
    elif task.headers["type"] == TaskType.WEBAPP:
        result = task.payload.get("url", None)
    elif task.headers["type"] == TaskType.URL:
        result = task.payload.get("url", None)
    elif task.headers["type"] == TaskType.SERVICE:
        if "host" in task.payload and "port" in task.payload:
            result = task.payload["host"] + ":" + str(task.payload["port"])
    elif task.headers["type"] == TaskType.DEVICE:
        if "host" in task.payload and "port" in task.payload:
            result = task.payload["host"] + ":" + str(task.payload["port"])

    if not result:
        result = task.headers["type"] + ": " + task.uid

    assert isinstance(result, str)
    return result


def has_ip_range(task: Task) -> bool:
    return "original_ip" in task.payload_persistent or "original_ip_range" in task.payload_persistent


def get_ip_range(task: Task) -> List[str]:
    if not has_ip_range(task):
        return []

    # The ordering here is important - we want to return the full IP range, not a single IP
    if "original_ip_range" in task.payload_persistent:
        ip_range = to_ip_range(task.payload_persistent["original_ip_range"])
        if not ip_range:
            ip_range = []
        return ip_range
    elif "original_ip" in task.payload_persistent:
        return [task.payload_persistent["original_ip"]]
    else:
        assert False
