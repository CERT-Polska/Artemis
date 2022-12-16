#!/usr/bin/env python3
import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict

from karton.core import Task

from artemis import request_limit
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.resolvers import ip_lookup
from artemis.resource_lock import ResourceLock
from artemis.task_utils import get_target

with open(os.path.join(os.path.dirname(__file__), "data", "ports-naabu.txt")) as f:
    PORTS_NAABU = ",".join([line for line in f if not line.startswith("#")])

PORTS_SET = set()

for port in PORTS_NAABU.split(","):
    port = port.strip()
    if not port:
        continue

    if "-" in port:
        port_from, port_to = port.split("-")
        for port_int in range(int(port_from), int(port_to) + 1):
            PORTS_SET.add(port_int)
    else:
        PORTS_SET.add(int(port))

# Additional ports we want to check for
PORTS_SET.add(23)  # telnet
PORTS_SET.add(139)  # SMB
PORTS_SET.add(445)  # SMB
PORTS_SET.add(6379)  # redis
PORTS_SET.add(8000)  # http
PORTS_SET.add(8080)  # http
PORTS_SET.add(3389)  # RDP
PORTS_SET.add(9200)  # Elasticsearch
PORTS_SET.add(27017)  # MongoDB
PORTS_SET.add(27018)  # MongoDB

PORTS = sorted(list(PORTS_SET))

NOT_INTERESTING_PORTS = [
    # None means "any port" - (None, "http") means "http on any port"
    (None, "ftp"),  # There is a module (artemis.modules.ftp_bruter) that checks FTP
    (None, "ssh"),  # We plan to add a check: https://github.com/CERT-Polska/Artemis/issues/35
    (None, "smtp"),  # There is a module (artemis.modules.postman) that checks SMTP
    (53, "dns"),  # Not worth reporting (DNS)
    (None, "http"),  # Regardles of what port the HTTP server is on, we will run related checks on that
    (None, "pop3"),
    (None, "imap"),
    (3306, "MySQL"),  # There is a module (artemis.modules.mysql_bruter) that checks MySQL
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
        with ResourceLock(redis=Config.REDIS, res_name="port_scanner-" + target_ip):
            naabu = subprocess.Popen(
                (
                    "naabu",
                    "-host",
                    target_ip,
                    "-port",
                    ",".join(map(str, PORTS)),
                    "-silent",
                    "-retries",
                    "1",
                    "-rate",
                    str(Config.SCANNING_PACKETS_PER_SECOND_PER_IP),
                ),
                stdout=subprocess.PIPE,
            )
            # We don't use `wait()` because of the following warning in the doc:
            #
            # This will deadlock when using stdout=PIPE and/or stderr=PIPE and the child process generates enough
            # output to a pipe such that it blocks waiting for the OS pipe buffer to accept more data. Use
            # communicate() to avoid that.
            stdout, stderr = naabu.communicate()
            if stderr:
                self.log.info(f"naabu returned the following stderr content: {stderr.decode('utf-8', errors='ignore')}")

        result: Dict[str, Dict[str, Any]] = {}
        if stdout:
            lines = stdout.split(b"\n")
        else:
            lines = []

        for line in lines:
            if not line:
                continue

            ip, _ = line.split(b":")

            request_limit.limit_requests_for_ip(ip.decode("ascii"))
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

                # Find whether relevant entries exist in the NOT_INTERESTING_PORTS list
                entry = (int(port), result["service"])
                entry_any_port = (None, result["service"])

                if entry not in NOT_INTERESTING_PORTS and entry_any_port not in NOT_INTERESTING_PORTS:
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
