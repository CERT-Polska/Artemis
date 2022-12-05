from karton.core import Task

from artemis.binds import Service, TaskType


def get_target(task: Task) -> str:
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

    raise ValueError("Unknown target found")


def get_target_url(task: Task) -> str:
    assert task.headers["service"] == Service.HTTP

    target = get_target(task)
    port = task.get_payload("port")
    protocol = "http"
    if task.get_payload("ssl"):
        protocol += "s"

    return f"{protocol}://{target}:{port}"
