#!/usr/bin/env python3
import ipaddress
import json
import re
import subprocess
from typing import List

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.domains import is_domain
from artemis.ip_utils import to_ip_range
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error

ASN_REGEX = "[aA][sS][0-9][0-9]*"


class RIPEAccessException(Exception):
    pass


def get_ip_prefixes_for_asn(asn: str) -> List[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn.upper()}"

    try:
        response = http_requests.get(url)
        if response.status_code == 200:
            data = response.json()
            prefixes = [item["prefix"] for item in data["data"]["prefixes"]]
            return prefixes

        raise RIPEAccessException(f"Error connecting to RIPEstat API.\nASN: {asn}\nError code: {response.status_code}")
    except Exception as err:
        raise RIPEAccessException(f"Error connecting to RIPEstat API.\nASN: {asn}\nError: {err}")
    return None


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
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

        if is_domain(data):
            # Just in case some downstream modules didn't support Unicode in
            # domains - let's encode them using IDNA
            data = data.encode("idna").decode("ascii")

        return data

    @staticmethod
    def _is_ip_or_domain(data: str) -> bool:

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
    def _clean_ipv6_brackets(data: str) -> str:
        if data.startswith("[") and data.endswith("]"):
            data = data[1:-1]
        return data

    @staticmethod
    def is_supported(data: str) -> bool:
        if re.match(ASN_REGEX, data):
            return True

        if to_ip_range(data):
            return True

        data = Classifier._clean_ipv6_brackets(data)

        if Classifier._is_ip_or_domain(data):
            return True

        if ":" not in data:
            return False

        data, port_str = data.rsplit(":", 1)

        try:
            int(port_str)
        except ValueError:
            return False

        data = Classifier._clean_ipv6_brackets(data)
        return Classifier._is_ip_or_domain(data)

    @staticmethod
    def _classify(data: str) -> TaskType:
        """
        :raises: ValueError if failed to find domain/IP
        """

        if Classifier._is_ip_or_domain(data):
            try:
                # if this doesn't throw then we have an IP address
                ipaddress.ip_address(data)
                return TaskType.IP
            except ValueError:
                pass

            if is_domain(data):
                return TaskType.DOMAIN
        else:
            return TaskType.SERVICE

        raise ValueError("Failed to find domain/IP in input")

    def run(self, current_task: Task) -> None:
        data = current_task.get_payload("data")

        data = data.lower()

        if not Classifier.is_supported(data):
            self.db.save_task_result(
                task=current_task, status=TaskStatus.ERROR, status_reason="Unsupported data: " + data
            )
            return

        data_as_ip_range = to_ip_range(data)
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
                            "original_ip_range": data,
                        },
                    ),
                )

            self.db.save_task_result(
                task=current_task, status=TaskStatus.OK, data={"type": TaskType.IP, "data": data_as_ip_range}
            )
            return

        if re.match(ASN_REGEX, data):
            ips = []
            for prefix in get_ip_prefixes_for_asn(data):
                self.log.info(f"Converted {data} to IP prefixes, processing {prefix}")
                if ":" in prefix:
                    self.log.error(
                        f"Skipping {prefix}, as it's an ipv6 prefix for an ASN - these might contain a large number of IPs"
                    )
                    continue

                for ip in list(map(str, ipaddress.ip_network(prefix.strip(), strict=False))):
                    self.add_task(
                        current_task,
                        Task(
                            {"type": TaskType.IP},
                            payload={
                                TaskType.IP.value: ip,
                            },
                            payload_persistent={
                                f"original_{TaskType.IP.value}": ip,
                                "original_ip_range": prefix,
                            },
                        ),
                    )
                    ips.append(ip)

            self.db.save_task_result(task=current_task, status=TaskStatus.OK, data={"type": TaskType.IP, "data": ips})
            return

        sanitized = self._sanitize(data)
        task_type = self._classify(sanitized)

        if task_type == TaskType.SERVICE:
            host, port_str = data.rsplit(":", 1)
            host = Classifier._clean_ipv6_brackets(host)
            port = int(port_str)

            if is_domain(host):
                host_type = "domain"
            else:
                host_type = "ip"

            try:
                output = self.throttle_request(
                    lambda: check_output_log_on_error(
                        ["fingerprintx", "--json"], self.log, input=data.encode("ascii")
                    ).strip()
                )
            except subprocess.CalledProcessError:
                self.log.exception("Unable to fingerprint %s", data)
                self.db.save_task_result(
                    task=current_task, status=TaskStatus.ERROR, status_reason="Unable to fingerprint: %s" % data
                )
                return

            if not output:
                self.log.exception("Unable to fingerprint %s", data)
                self.db.save_task_result(
                    task=current_task, status=TaskStatus.ERROR, status_reason="Unable to fingerprint: %s" % data
                )
                return

            data = json.loads(output)
            ssl = data["tls"]
            service = data["protocol"]
            if ssl:
                # If the service is a SSL service, fingerprintx will append s (e.g. `https`) to the end of the name
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
            self.db.save_task_result(
                task=current_task, status=TaskStatus.OK, data={"type": task_type, "data": [sanitized]}
            )
        else:
            data = Classifier._clean_ipv6_brackets(data)

            if task_type == TaskType.DOMAIN:
                self.add_task(
                    current_task,
                    Task(
                        {"type": TaskType.DOMAIN_THAT_MAY_NOT_EXIST},
                        payload={
                            task_type.value: sanitized,
                        },
                        payload_persistent={
                            f"original_{task_type.value}": sanitized,
                        },
                    ),
                )

            new_task = Task(
                {"type": task_type},
                payload={
                    task_type.value: sanitized,
                },
                payload_persistent={
                    f"original_{task_type.value}": sanitized,
                },
            )

            if self.add_task_if_domain_exists(current_task, new_task):
                self.db.save_task_result(
                    task=current_task, status=TaskStatus.OK, data={"type": task_type, "data": [sanitized]}
                )
            else:
                self.db.save_task_result(
                    task=current_task,
                    status=TaskStatus.ERROR,
                    status_reason="Domain doesn't exist or is a placeholder page",
                )


if __name__ == "__main__":
    Classifier().loop()
