#!/usr/bin/env python3

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Dict

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.resolvers import ip_lookup

NOT_INTERESTING_PORTS = [
    # There are other kartons checking whether services on these ports are interesting
    (21, "ftp"),
    (25, "smtp"),
    (80, "http"),
    (443, "http"),
] + [
    (22, "ssh"),  # We plan to add a check: https://github.com/CERT-Polska/Artemis/issues/35
    (53, "dns"),  # Not worth reporting (DNS)
]


class PortScanner(ArtemisBase):
    """
    Consumes `type: IP`, scans them with naabu and fingerprintx and produces
    tasks separated into services (eg. `type: http`)
    """

    # We want to scan domains (but maybe using cached results for given IP) so that if there
    # are multiple domains for a single IP, service entries will get created for each one (which
    # matters e.g. for HTTP vhosts).
    identity = "port_scanner"
    filters = [
        {"type": TaskType.IP},
        {"type": TaskType.DOMAIN},
    ]

    @dataclass
    class PortResult:
        service: Service
        ssl: bool

    def _scan(self, target_ip: str) -> Dict[str, Dict[str, Any]]:
        # We deduplicate identical tasks, but even if two task are different (e.g. contain
        # different domain names), they may point to the same IP, and therefore scanning both
        # would be a waste of resources.
        if cache := self.cache.get(target_ip):
            self.log.info(f"host {target_ip} in redis cache")
            return json.loads(cache)  # type: ignore

        self.log.info(f"scanning {target_ip}")
        naabu = subprocess.Popen(
            ("naabu", "-host", target_ip, "-top-ports", "1000", "-silent"),
            stdout=subprocess.PIPE,
        )
        fingerprintx = subprocess.check_output(("fingerprintx", "--json"), stdin=naabu.stdout)
        naabu.wait()

        result: Dict[str, Dict[str, Any]] = {}
        for line in fingerprintx.decode().split("\n"):
            if not line:
                continue

            data = json.loads(line)
            port = int(data["port"])
            ssl = data["transport"] == "tcptls"
            service = data["service"]
            if ssl:
                service = service.rstrip("s")

            result[str(port)] = self.PortResult(service, ssl).__dict__

        self.cache.set(target_ip, json.dumps(result).encode("utf-8"))
        return result

    def run(self, current_task: Task) -> None:
        target = self.get_target(current_task)
        task_type = current_task.headers["type"]

        # convert domain to IPs
        if task_type == TaskType.DOMAIN:
            hosts = ip_lookup(target)
        elif task_type == TaskType.IP:
            hosts = {target}
        else:
            raise ValueError("Unknown task type")

        all_results = {}
        open_ports = []
        interesting_port_descriptions = []
        for host in hosts:
            scan_results = self._scan(host)
            all_results[host] = scan_results

            for port, result in all_results[host].items():
                new_task = Task(
                    {
                        "type": TaskType.SERVICE,
                        "service": Service(result["service"]),
                    },
                    payload={
                        "host": target,
                        "port": int(port),
                        "ssl": result["ssl"],
                    },
                )
                self.add_task(current_task, new_task)
                open_ports.append(int(port))
                if (int(port), result["service"]) not in NOT_INTERESTING_PORTS:
                    interesting_port_descriptions.append(f"{port} (service: {result['service']} ssl: {result['ssl']})")

        if len(interesting_port_descriptions):
            status = TaskStatus.INTERESTING
            status_reason = "Found ports: " + ", ".join(sorted(interesting_port_descriptions))
        else:
            status = TaskStatus.OK
            status_reason = None
        # save raw results
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=all_results)


if __name__ == "__main__":
    PortScanner().loop()
