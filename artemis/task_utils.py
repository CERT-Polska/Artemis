import urllib

from karton.core import Task

from artemis.binds import Service, TaskType


def get_target_host(task: Task) -> str:
    task_type = task.headers["type"]

    if task_type == TaskType.SERVICE:
        payload = task.get_payload("host")
        assert isinstance(payload, str)
        return payload

    if task_type == TaskType.DOMAIN:
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
