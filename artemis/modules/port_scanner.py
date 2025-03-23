#!/usr/bin/env python3
import collections
import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Set

import requests
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.resolvers import lookup
from artemis.task_utils import get_target_host
from artemis.utils import check_output_log_on_error


def load_ports(file_name: str) -> Set[int]:
    with open(os.path.join(os.path.dirname(__file__), "data", file_name)) as f:
        ports = ",".join([line for line in f if not line.startswith("#")])

    result: Set[int] = set()
    for port in ports.split(","):
        port = port.strip()
        if not port:
            continue

        if "-" in port:
            port_from, port_to = port.split("-")
            for port_int in range(int(port_from), int(port_to) + 1):
                result.add(port_int)
        else:
            result.add(int(port))
    return result


if Config.Modules.PortScanner.CUSTOM_PORT_SCANNER_PORTS:
    PORTS_SET = set(Config.Modules.PortScanner.CUSTOM_PORT_SCANNER_PORTS)

else:
    if Config.Modules.PortScanner.PORT_SCANNER_PORT_LIST not in ["short", "long"]:
        raise ValueError(
            "Unable to start port scanner - Config.Modules.PortScanner.PORT_LIST should be `short` or `long`"
        )

    if Config.Modules.PortScanner.PORT_SCANNER_PORT_LIST == "short":
        PORTS_SET = load_ports("ports-artemis-short.txt")
    else:
        PORTS_SET = load_ports("ports-naabu.txt") | {
            23,  # telnet
            139,  # SMB
            445,  # SMB
            4433,  # FortiOS
            6379,  # redis
            8000,  # http
            8080,  # http
            3389,  # RDP
            9200,  # Elasticsearch
            9443,  # FortiOS
            10443,  # FortiOS
            27017,  # MongoDB
            27018,  # MongoDB
        }

    PORTS_SET_SHORT = load_ports("ports-artemis-short.txt")

PORTS = sorted(list(PORTS_SET))


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class PortScanner(ArtemisBase):
    """
    Consumes `type: IP` or `type: DOMAIN`, scans them with naabu and fingerprintx and produces
    SERVICE tasks for each service detected on a port (eg. `type: http`).
    """

    # We want to scan domains (but maybe using cached results for given IP) so that if there
    # are multiple domains for a single IP, service entries will get created for each one (which
    # matters e.g. for HTTP vhosts).
    identity = "port_scanner"
    filters = [
        {"type": TaskType.IP.value},
        {"type": TaskType.DOMAIN.value},
    ]
    batch_tasks = True
    task_max_batch_size = Config.Modules.PortScanner.PORT_SCANNER_MAX_BATCH_SIZE

    @dataclass
    class PortResult:
        service: Service
        ssl: bool
        version: str

    def _scan(self, target_ips: List[str]) -> Dict[str, Dict[str, Dict[str, Any]]]:
        result: Dict[str, Dict[str, Dict[str, Any]]] = {}

        new_target_ips = []
        for target_ip in target_ips:
            # We deduplicate identical tasks, but even if two task are different (e.g. contain
            # different domain names), they may point to the same IP, and therefore scanning both
            # would be a waste of resources.
            if (cache := self.cache.get(target_ip)) is not None:
                self.log.info(f"host {target_ip} in redis cache")
                result[target_ip] = json.loads(cache)
            else:
                new_target_ips.append(target_ip)

        if new_target_ips:
            self.log.info(f"scanning {new_target_ips}")
            time_start = time.time()
            naabu = subprocess.Popen(
                [
                    "naabu",
                    "-host",
                    ",".join(new_target_ips),
                    "-port",
                    ",".join(map(str, PORTS)),
                    "-silent",
                    "-input-read-timeout",
                    "1s",
                    "-timeout",
                    str(Config.Modules.PortScanner.PORT_SCANNER_TIMEOUT_MILLISECONDS),
                ]
                + (
                    ["-rate", str(max(1, int(self.requests_per_second_for_current_tasks)) * len(new_target_ips))]
                    if int(self.requests_per_second_for_current_tasks)
                    else []
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

            self.log.info(f"scanning of {new_target_ips} took {time.time()  - time_start} seconds")

            if stdout:
                lines = stdout.decode("ascii").split("\n")
            else:
                lines = []

            time_start = time.time()
            lines = [line for line in lines if line]
            found_ports: Dict[str, List[str]] = collections.defaultdict(list)

            for line in lines:
                ip, port_str = line.split(":")
                found_ports[ip].append(port_str)

            if Config.Modules.PortScanner.ADD_PORTS_FROM_SHODAN_INTERNETDB:
                for new_target_ip in new_target_ips:
                    data = requests.get("https://internetdb.shodan.io/" + new_target_ip).json()
                    for port in data["ports"]:
                        self.log.info(f"Detected port {port} on {new_target_ip} from Shodan internetdb")
                        found_ports[new_target_ip].append(str(port))

            for ip in found_ports.keys():
                if len(found_ports[ip]) > Config.Modules.PortScanner.PORT_SCANNER_MAX_NUM_PORTS:
                    self.log.warning(
                        "We observed more than %s open ports on %s, trimming to most popular ones",
                        Config.Modules.PortScanner.PORT_SCANNER_MAX_NUM_PORTS,
                        ip,
                    )
                    found_ports[ip] = [port_str for port_str in found_ports[ip] if int(port_str) in PORTS_SET_SHORT]

            for ip in found_ports:
                for port_str in found_ports[ip]:
                    try:
                        output = self.throttle_request(
                            lambda: check_output_log_on_error(
                                ["fingerprintx", "--json"], self.log, input=f"{ip}:{port_str}".encode("ascii")
                            ).strip()
                        )
                    except subprocess.CalledProcessError:
                        self.log.exception("Unable to fingerprint %s", line)
                        continue

                    if not output:
                        continue

                    data = json.loads(output)
                    port = int(data["port"])
                    ssl = data["tls"]
                    service = data["protocol"]
                    version = data.get("version", None) or data.get("metadata", {}).get("fingerprint", None) or "N/A"
                    if ssl:
                        service = service.rstrip("s")

                    if ip not in result:
                        result[ip] = {}
                    result[ip][str(port)] = self.PortResult(service, ssl, version).__dict__

            self.log.info(f"fingerprinting of {new_target_ips} took {time.time()  - time_start} seconds")

            for target_ip in new_target_ips:
                self.cache.set(target_ip, json.dumps(result.get(target_ip, {})).encode("utf-8"))
        return result

    def run_multiple(self, tasks: List[Task]) -> None:
        hosts_per_task = {}
        hosts: List[str] = []

        for task in tasks:
            target = get_target_host(task)
            task_type = task.headers["type"]

            # convert domain to IPs
            if task_type == TaskType.DOMAIN:
                hosts_per_task[task] = lookup(target)
            elif task_type == TaskType.IP:
                hosts_per_task[task] = {target}
            else:
                raise ValueError("Unknown task type")
            hosts.extend(hosts_per_task[task])

        scan_results = self._scan(hosts)

        for task in tasks:
            target = get_target_host(task)
            all_results = {}
            open_ports = []
            interesting_port_descriptions = []
            for host in hosts_per_task[task]:
                all_results[host] = scan_results.get(host, {})

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

                    self.add_task(task, new_task)
                    open_ports.append(int(port))

                    interesting_port_descriptions.append(
                        f"{port} (service: {result['service']} ssl: {result['ssl']}, version: {result['version']})"
                    )

            if len(interesting_port_descriptions):
                status = TaskStatus.INTERESTING
                status_reason = "Found ports: " + ", ".join(sorted(interesting_port_descriptions))
            else:
                status = TaskStatus.OK
                status_reason = None
            # save raw results
            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=all_results)


if __name__ == "__main__":
    PortScanner().loop()
