#!/usr/bin/env python3
import re
from ipaddress import ip_address

from karton.core import Task
from publicsuffixlist import PublicSuffixList

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase

domain_pattern = re.compile(
    r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
    r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$"
)


PUBLIC_SUFFIX_LIST = PublicSuffixList()


class Classifier(ArtemisBase):
    """
    Collects `type: new` and converts them to `type: HAS_DOMAIN` or `type: HAS_IP`
    Expects data to be in `payload["data"]`.
    """

    identity = "classifier"
    filters = [
        {"type": TaskType.NEW},
    ]

    @staticmethod
    def _sanitize(data: str) -> str:
        # replace common tricks
        data = data.replace("[.]", ".")

        # strip URL schemes
        for x in ["https", "hxxps", "http", "hxxp", "git", "gopher", "imap", "ssh", "ws"]:
            data = data.removeprefix(x + "://")

        # strip after slash
        if "/" in data:
            data = data.split("/")[0]

        # if contains '@', then split after
        if "@" in data:
            data = data.split("@")[1]

        # split last ":" (port)
        if ":" in data:
            data = data.rsplit(":")[0]

        # Strip leading and trailing dots (e.g. domain.com.)
        data = data.strip(".")

        return data

    @staticmethod
    def _classify(data: str) -> TaskType:
        """
        :raises: ValueError if failed to find domain/IP
        """
        try:
            # if this doesn't throw then we have an IP address
            ip_address(data)
            return TaskType.IP
        except ValueError:
            pass

        if domain_pattern.match(data):
            return TaskType.DOMAIN
        else:
            raise ValueError("Failed to find domain/IP in input")

    def run(self, current_task: Task) -> None:
        data = current_task.get_payload("data")
        sanitized = self._sanitize(data)
        task_type = self._classify(sanitized)

        if task_type == TaskType.DOMAIN:
            if (
                PUBLIC_SUFFIX_LIST.publicsuffix(sanitized) == sanitized
                or sanitized in Config.ADDITIONAL_PUBLIC_SUFFIXES
            ):
                if not Config.ALLOW_SCANNING_PUBLIC_SUFFIXES:
                    message = (
                        f"{sanitized} is a public suffix - adding it to the list of "
                        "scanned targets may result in scanning too much. Quitting."
                    )
                    self.log.warning(message)
                    self.db.save_task_result(
                        task=current_task, status=TaskStatus.ERROR, status_reason=message, data=task_type
                    )
                    return

        new_task = Task(
            {"type": task_type},
            payload={
                task_type: sanitized,
            },
            payload_persistent={
                f"original_{task_type.value}": sanitized,
            },
        )

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=new_task.headers["type"])
        self.add_task(current_task, new_task)


if __name__ == "__main__":
    Classifier().loop()
