#!/usr/bin/env python3
import ipaddress
import urllib.parse
from typing import List, Optional

from karton.core import Task
from publicsuffixlist import PublicSuffixList

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_domain
from artemis.module_base import ArtemisBase
from artemis.utils import is_ip_address

PUBLIC_SUFFIX_LIST = PublicSuffixList()


class Classifier(ArtemisBase):
    """
    Collects `type: new` and converts them to `type: HAS_DOMAIN` or `type: HAS_IP`
    Expects data to be in `payload["data"]`.
    """

    identity = "classifier"
    filters = [
        {"type": TaskType.NEW.value},
    ]

    @staticmethod
    def _sanitize(data: str) -> str:
        if "hxxp://" in data.lower() or "hxxps://" in data.lower() or "[.]" in data:
            raise RuntimeError(
                "Defanged URL detected. If you really want to scan it, please provide it as a standard one."
            )

        # strip URL schemes
        if "://" in data:
            hostname = urllib.parse.urlparse(data).hostname
            assert hostname is not None
            data = hostname

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
            ipaddress.ip_address(data)
            return TaskType.IP
        except ValueError:
            pass

        if is_domain(data):
            return TaskType.DOMAIN

        raise ValueError("Failed to find domain/IP in input")

    @staticmethod
    def _to_ip_range(data: str) -> Optional[List[str]]:
        if "-" in data:
            start_ip_str, end_ip_str = data.split("-", 1)
            start_ip_str = start_ip_str.strip()
            end_ip_str = end_ip_str.strip()

            if not is_ip_address(start_ip_str) or not is_ip_address(end_ip_str):
                return None

            start_ip = ipaddress.IPv4Address(start_ip_str)
            end_ip = ipaddress.IPv4Address(end_ip_str)

            return [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
        if "/" in data:
            ip, mask = data.split("/", 1)
            ip = ip.strip()
            mask = mask.strip()

            if not is_ip_address(ip) or not mask.isdigit():
                return None

            return list(map(str, ipaddress.IPv4Network(data.strip(), strict=False)))
        return None

    def run(self, current_task: Task) -> None:
        data = current_task.get_payload("data")

        data_as_ip_range = self._to_ip_range(data)
        if data_as_ip_range:
            for ip in data_as_ip_range:
                self.add_task(
                    current_task,
                    Task(
                        {"type": TaskType.IP},
                        payload={
                            TaskType.IP.value: ip,
                        },
                        payload_persistent={
                            f"original_{TaskType.IP.value}": ip,
                        },
                    ),
                )

            self.db.save_task_result(
                task=current_task, status=TaskStatus.OK, data={"type": TaskType.IP, "data": data_as_ip_range}
            )
            return

        sanitized = self._sanitize(data)
        task_type = self._classify(sanitized)

        if task_type == TaskType.DOMAIN:
            if (
                PUBLIC_SUFFIX_LIST.publicsuffix(sanitized) == sanitized
                or sanitized in Config.PublicSuffixes.ADDITIONAL_PUBLIC_SUFFIXES
            ):
                if not Config.PublicSuffixes.ALLOW_SCANNING_PUBLIC_SUFFIXES:
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
                task_type.value: sanitized,
            },
            payload_persistent={
                f"original_{task_type.value}": sanitized,
            },
        )

        self.db.save_task_result(
            task=current_task, status=TaskStatus.OK, data={"type": new_task.headers["type"], "data": [sanitized]}
        )
        self.add_task(current_task, new_task)


if __name__ == "__main__":
    Classifier().loop()
