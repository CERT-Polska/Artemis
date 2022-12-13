#!/usr/bin/env python3
import json
import subprocess
from dataclasses import dataclass
from typing import Any, Dict

from karton.core import Task

from artemis import request_limit
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisSingleTaskBase
from artemis.resolvers import ip_lookup
from artemis.resource_lock import ResourceLock
from artemis.task_utils import get_target

NOT_INTERESTING_PORTS = [
    # There are other kartons checking whether services on these ports are interesting
    (21, "ftp"),  # There is a module that checks FTP
    (22, "ssh"),  # We plan to add a check: https://github.com/CERT-Polska/Artemis/issues/35
    (25, "smtp"),
    (53, "dns"),  # Not worth reporting (DNS)
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "http"),
    (587, "smtp"),
    (993, "imap"),
    (995, "pop3"),
    (3306, "MySQL"),  # There is a module that checks MySQL
]


class PortScanner(ArtemisSingleTaskBase):
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
        with ResourceLock(redis=Config.REDIS, res_name="port_scanner-" + target_ip):
            naabu = subprocess.Popen(
                (
                    "naabu",
                    "-host",
                    target_ip,
                    "-top-ports",
                    "1000",
                    "-silent",
                    "-rate",
                    str(Config.SCANNING_PACKETS_PER_SECOND_PER_IP),
                ),
                stdout=subprocess.PIPE,
            )
            naabu.wait()

        result: Dict[str, Dict[str, Any]] = {}
        if naabu.stdout:
            lines = naabu.stdout.read().split(b"\n")
            naabu.stdout.close()
        else:
            lines = []

        for line in lines:
            if not line:
                continue

            ip, _ = line.split(b":")

            request_limit.limit_requests_for_the_same_ip(ip.decode("ascii"))
            output = subprocess.check_output(["fingerprintx", "--json"], input=line).strip()

            if not output:
                continue

            data = json.loads(output)
            port = int(data["port"])
            ssl = data["transport"] == "tcptls"
            service = data["service"]
            if ssl:
                service = service.rstrip("s")

            result[str(port)] = self.PortResult(service, ssl).__dict__

        self.cache.set(target_ip, json.dumps(result).encode("utf-8"))
        return result

    def run(self, current_task: Task) -> None:
        target = get_target(current_task)
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
                        "service": Service(result["service"].lower()),
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
