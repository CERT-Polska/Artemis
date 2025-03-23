#!/usr/bin/env python3
import collections
import enum
import itertools
import json
import os
import random
import shutil
import subprocess
import time
import urllib
from statistics import StatisticsError, quantiles
from typing import Any, Callable, Dict, List

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.task_utils import get_target_host, get_target_url
from artemis.utils import (
    check_output_log_on_error,
    check_output_log_on_error_with_stderr,
)

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")
TAGS_TO_INCLUDE = ["fuzz", "fuzzing", "dast"]


class ScanUsing(enum.Enum):
    TEMPLATES = "templates"
    WORKFLOWS = "workflows"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class Nuclei(ArtemisBase):
    """
    Runs Nuclei templates on URLs.
    """

    identity = "nuclei"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    batch_tasks = True
    task_max_batch_size = Config.Modules.Nuclei.NUCLEI_MAX_BATCH_SIZE

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        # We clone this repo in __init__ (on karton start) so that it will get periodically
        # re-cloned when the container gets retarted every 𝑛 tasks. The same logic lies behind
        # updating the Nuclei templates in __init__.
        if os.path.exists("/known-exploited-vulnerabilities/"):
            shutil.rmtree("/known-exploited-vulnerabilities/")

        subprocess.call(["git", "clone", "https://github.com/Ostorlab/KEV/", "/known-exploited-vulnerabilities/"])
        with self.lock:
            # Cleanup so that no old template files exist
            template_directory = "/root/nuclei-templates/"
            if os.path.exists(template_directory) and os.path.getctime(template_directory) < time.time() - 3600:
                shutil.rmtree(template_directory, ignore_errors=True)
                shutil.rmtree("/root/.config/nuclei/", ignore_errors=True)

            subprocess.call(["nuclei", "-update-templates"])

            templates_list_command = ["-tl", "-it", ",".join(TAGS_TO_INCLUDE)]

            template_list_sources: Dict[str, Callable[[], List[str]]] = {
                "known_exploited_vulnerabilities": lambda: [
                    item
                    for item in check_output_log_on_error(
                        ["find", "/known-exploited-vulnerabilities/nuclei/"], self.log
                    )
                    .decode("ascii")
                    .split()
                    if item.endswith(".yml") or item.endswith(".yaml")
                ],
                "critical": lambda: check_output_log_on_error(
                    ["nuclei", "-s", "critical"] + templates_list_command, self.log
                )
                .decode("ascii")
                .split(),
                "high": lambda: check_output_log_on_error(["nuclei", "-s", "high"] + templates_list_command, self.log)
                .decode("ascii")
                .split(),
                "medium": lambda: check_output_log_on_error(
                    ["nuclei", "-s", "medium"] + templates_list_command, self.log
                )
                .decode("ascii")
                .split(),
                # These are not high severity, but may lead to significant information leaks and are easy to fix
                "log_exposures": lambda: [
                    item
                    for item in check_output_log_on_error(["nuclei"] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                    if item.startswith("http/exposures/logs")
                    # we already have a git detection module that filters FPs such as
                    # exposed source code of a repo that is already public
                    and not item.startswith("http/exposures/logs/git-")
                ],
                "exposed_panels": lambda: [
                    item
                    for item in check_output_log_on_error(["nuclei"] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                    if item.startswith(EXPOSED_PANEL_TEMPLATE_PATH_PREFIX)
                ],
            }

            self._templates = Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES
            for name in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                if name not in template_list_sources:
                    raise Exception(f"Unknown template list: {name}")
                template_list = template_list_sources[name]()

                if Config.Modules.Nuclei.NUCLEI_CHECK_TEMPLATE_LIST:
                    if len(template_list) == 0:
                        raise RuntimeError(f"Unable to obtain Nuclei templates for list {name}")

                for template in template_list:
                    if template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP:
                        self._templates.append(template)

            for custom_template_filename in os.listdir(CUSTOM_TEMPLATES_PATH):
                self._templates.append(os.path.join(CUSTOM_TEMPLATES_PATH, custom_template_filename))

            self._workflows = [os.path.join(os.path.dirname(__file__), "data", "nuclei_workflows_custom", "workflows")]

        self._nuclei_templates_or_workflows_to_skip_probabilistically_set = set()
        if Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE:
            for line in open(Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE):
                self._nuclei_templates_or_workflows_to_skip_probabilistically_set.add(line.strip())

    def _get_links(self, url: str) -> List[str]:
        links = get_links_and_resources_on_same_domain(url)
        random.shuffle(links)

        links = [
            link
            for link in links
            if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
        ]

        links = links[: Config.Modules.Nuclei.NUCLEI_MAX_NUM_LINKS_TO_PROCESS]
        return links

    def _strip_query_string(self, url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    def _get_requests_per_second_statistics(sef, stderr_lines: List[str]) -> str:
        current_second_host_requests: Dict[str, int] = collections.defaultdict(int)
        requests_per_second_per_host: List[int] = []

        def _finish_current_second() -> None:
            nonlocal requests_per_second_per_host
            nonlocal current_second_host_requests

            requests_per_second_per_host.extend(current_second_host_requests.values())
            current_second_host_requests = collections.defaultdict(int)

        for line in stderr_lines:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "duration" in data and "requests" in data:  # stats line
                _finish_current_second()
            elif "address" in data:  # request info line
                current_second_host_requests[data["address"].split(":")[0]] += 1
        _finish_current_second()

        try:
            requests_per_second_per_host_quantiles = quantiles(requests_per_second_per_host, n=100)

            requests_per_second_per_host_75_percentile = requests_per_second_per_host_quantiles[75 - 1]
            requests_per_second_per_host_95_percentile = requests_per_second_per_host_quantiles[95 - 1]
            requests_per_second_per_host_99_percentile = requests_per_second_per_host_quantiles[99 - 1]
        except StatisticsError:
            requests_per_second_per_host_75_percentile = None
            requests_per_second_per_host_95_percentile = None
            requests_per_second_per_host_99_percentile = None

        return "Max requests per second for a single host: %s, 75 percentile %s, 95 percentile %s, 99 percentile %s" % (
            max(requests_per_second_per_host) if requests_per_second_per_host else None,
            requests_per_second_per_host_75_percentile,
            requests_per_second_per_host_95_percentile,
            requests_per_second_per_host_99_percentile,
        )

    def _scan(
        self, templates_or_workflows: List[str], scan_using: ScanUsing, targets: List[str]
    ) -> List[Dict[str, Any]]:
        if not targets:
            return []

        templates_or_workflows_filtered = []

        num_templates_or_workflows_skipped = 0
        for template_or_workflow in templates_or_workflows:
            if template_or_workflow not in self._nuclei_templates_or_workflows_to_skip_probabilistically_set:
                templates_or_workflows_filtered.append(template_or_workflow)
            elif (
                template_or_workflow in self._nuclei_templates_or_workflows_to_skip_probabilistically_set
                and random.uniform(0, 100)
                >= Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY
            ):
                templates_or_workflows_filtered.append(template_or_workflow)
            else:
                num_templates_or_workflows_skipped += 1

        self.log.info(
            "Requested to skip %d templates or workflows with probability %f, actually skipped %d",
            len(self._nuclei_templates_or_workflows_to_skip_probabilistically_set),
            Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY,
            num_templates_or_workflows_skipped,
        )
        self.log.info(
            "After probabilistic skipping, executing %d templates or workflows out of %d",
            len(templates_or_workflows_filtered),
            len(templates_or_workflows),
        )

        if self.requests_per_second_for_current_tasks:
            milliseconds_per_request_initial = int(
                (1 / self.requests_per_second_for_current_tasks) * 1000.0 / len(targets)
            )
        else:
            milliseconds_per_request_initial = 0

        if not milliseconds_per_request_initial:
            milliseconds_per_request_initial = 1  # 0 will make Nuclei wait 1 second

        milliseconds_per_request_candidates = [
            milliseconds_per_request_initial,
            int(
                max(
                    1000 * Config.Modules.Nuclei.NUCLEI_SECONDS_PER_REQUEST_ON_RETRY,
                    milliseconds_per_request_initial * 2,
                )
            ),
        ]

        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            additional_configuration = ["-H", "User-Agent: " + Config.Miscellaneous.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        lines = []
        for chunk in more_itertools.chunked(templates_or_workflows_filtered, Config.Modules.Nuclei.NUCLEI_CHUNK_SIZE):
            for milliseconds_per_request in milliseconds_per_request_candidates:
                self.log.info(
                    "Running batch of %d templates or workflows on %d target(s), milliseconds_per_request=%d",
                    len(chunk),
                    len(targets),
                    milliseconds_per_request,
                )
                command = [
                    "nuclei",
                    "-disable-update-check",
                    "-itags",
                    ",".join(TAGS_TO_INCLUDE),
                    "-v",
                    "-timeout",
                    str(Config.Limits.REQUEST_TIMEOUT_SECONDS),
                    "-jsonl",
                    "-system-resolvers",
                    "-rate-limit",
                    "1",
                    "-rate-limit-duration",
                    str(milliseconds_per_request) + "ms",
                    "-stats-json",
                    "-stats-interval",
                    "1",
                    "-trace-log",
                    "/dev/stderr",
                ] + additional_configuration

                if scan_using == ScanUsing.TEMPLATES:
                    command.extend(
                        [
                            "-templates",
                            ",".join(chunk),
                        ]
                    )
                elif scan_using == ScanUsing.WORKFLOWS:
                    command.extend(
                        [
                            "-workflows",
                            ",".join(chunk),
                        ]
                    )
                else:
                    assert False

                if Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER:
                    command.extend(["-interactsh-server", Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER])

                if scan_using == ScanUsing.TEMPLATES:
                    # The `-it` flag will include the templates provided in NUCLEI_ADDITIONAL_TEMPLATES even if
                    # they're marked with as tag such as `fuzz` which prevents them from being executed by default.
                    for template in Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES:
                        if template in chunk:
                            command.append("-it")
                            command.append(template)

                for target in targets:
                    command.append("-target")
                    command.append(target)

                self.log.debug("Running command: %s", " ".join(command))
                stdout, stderr = check_output_log_on_error_with_stderr(command, self.log)

                stdout_utf8 = stdout.decode("utf-8", errors="ignore")
                stderr_utf8 = stderr.decode("utf-8", errors="ignore")

                stdout_utf8_lines = stdout_utf8.split("\n")
                stderr_utf8_lines = stderr_utf8.split("\n")

                for line in stdout_utf8_lines:
                    if line.startswith("{"):
                        self.log.info("Found: %s...", line[:100])
                        self.log.debug("%s", line)
                        lines.append(line)

                self.log.info(
                    "Requests per second statistics: %s", self._get_requests_per_second_statistics(stderr_utf8_lines)
                )

                if "context deadline exceeded" in stdout_utf8 + stderr_utf8:
                    self.log.info(
                        "Detected %d occurencies of 'context deadline exceeded'",
                        (stdout_utf8 + stderr_utf8).count("context deadline exceeded"),
                    )
                    new_milliseconds_per_request_candidates = [
                        item for item in milliseconds_per_request_candidates if item > milliseconds_per_request
                    ]
                    if len(new_milliseconds_per_request_candidates) > 0:
                        milliseconds_per_request_candidates = new_milliseconds_per_request_candidates
                        self.log.info("Retrying with longer timeout")
                    else:
                        self.log.info("Can't retry with longer timeout")

                else:
                    break

        findings = []
        for line in lines:
            if line.strip():
                finding = json.loads(line)
                findings.append(finding)
        return findings

    def run_multiple(self, tasks: List[Task]) -> None:
        self.log.info(f"running {len(self._templates)} templates and {len(self._workflows)} on {len(tasks)} hosts.")

        targets = []
        for task in tasks:
            targets.append(get_target_url(task))

        links_per_task = {}
        for task in tasks:
            links = self._get_links(get_target_url(task))
            # Let's scan both links with stripped query strings and with original one. We may catch a bug on either
            # of them.
            links_per_task[task.uid] = list(set(links) | set([self._strip_query_string(link) for link in links]))
            self.log.info("Links for %s: %s", get_target_url(task), links_per_task[task.uid])

        findings = self._scan(self._templates, ScanUsing.TEMPLATES, targets) + self._scan(
            self._workflows, ScanUsing.WORKFLOWS, targets
        )

        # That way, if we have 100 links for a webpage, we won't run 100 concurrent scans for that webpage
        for link_package in itertools.zip_longest(*list(links_per_task.values())):
            findings.extend(
                self._scan(
                    Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS,
                    ScanUsing.TEMPLATES,
                    [item for item in link_package if item],
                )
            )

        findings_per_task = collections.defaultdict(list)
        findings_unmatched = []
        for finding in findings:
            found = False
            for task in tasks:
                if finding["url"] in [get_target_url(task)] + links_per_task[task.uid]:
                    findings_per_task[task.uid].append(finding)
                    found = True
                    break
            if not found:
                findings_unmatched.append(finding)

        if findings_unmatched:
            self.log.info("Findings unmatched: %s", repr(findings_unmatched))

            for finding in findings_unmatched:
                found = False
                for task in tasks:
                    if finding["host"].split(":")[0] == get_target_host(task).split(":")[0]:
                        findings_per_task[task.uid].append(finding)
                        found = True
                        break
                assert found, "Cannot match finding: %s" % finding

        for task in tasks:
            result = []
            messages = []

            for finding in findings_per_task[task.uid]:
                result.append(finding)
                messages.append(
                    f"[{finding['info']['severity']}] {finding['url']}: {finding['info'].get('name')} {finding['info'].get('description')}"
                )

            if messages:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join(sorted(messages))
            else:
                status = TaskStatus.OK
                status_reason = None
            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    Nuclei().loop()
