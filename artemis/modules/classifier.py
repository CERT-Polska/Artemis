#!/usr/bin/env python3
import ipaddress
import json
import subprocess
from typing import List, Optional

from karton.core import Task
from publicsuffixlist import PublicSuffixList

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_domain
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error, is_ip_address, throttle_request

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
        data = data.lower()

        # Strip leading and trailing dots (e.g. domain.com.)
        data = data.strip(".")

        return data

    @staticmethod
    def is_supported(data: str) -> bool:
        if Classifier._to_ip_range(data):
            return True

        if ":" in data:
            data, port = data.split(":", 1)

            try:
                int(port)
            except ValueError:
                return False

        try:
            # if this doesn't throw then we have an IP address
            ipaddress.ip_address(data)
            return True
        except ValueError:
            pass

        if is_domain(data):
            return True

        return False

    @staticmethod
    def _classify(data: str) -> TaskType:
        """
        :raises: ValueError if failed to find domain/IP
        """

        if ":" in data:
            return TaskType.SERVICE

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
        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data={"type": task_type, "data": [sanitized]})

        if task_type == TaskType.SERVICE:
            host, port_str = data.split(":")
            port = int(port_str)

            if is_domain(host):
                host_type = "domain"
            else:
                host_type = "ip"

            try:
                output = throttle_request(
                    lambda: check_output_log_on_error(
                        ["fingerprintx", "--json"], self.log, input=data.encode("ascii")
                    ).strip()
                )
            except subprocess.CalledProcessError:
                self.log.exception("Unable to fingerprint %s", data)
                return

            if not output:
                self.log.exception("Unable to fingerpritn %s", data)
                return

            data = json.loads(output)
            ssl = data["tls"]
            service = data["protocol"]
            if ssl:
                service = service.rstrip("s")

            self.log.info("%s identified to be %s", data, service)

            new_task = Task(
                {
                    "type": TaskType.SERVICE,
                    "service": Service(service.lower()),
                },
                payload={"host": host, "port": port, "ssl": ssl, **({"last_domain": host} if is_domain(host) else {})},
                payload_persistent={
                    f"original_{host_type}": host,
                },
            )
            self.add_task(current_task, new_task)
        else:
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

            self.add_task(current_task, new_task)


if __name__ == "__main__":
    Classifier().loop()
