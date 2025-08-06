#!/usr/bin/env python3
import collections
import enum
import itertools
import json
import logging
import os
import random
import urllib
from statistics import StatisticsError, quantiles
from typing import Any, Dict, List

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.modules.base.runtime_configuration_registry import (
    RuntimeConfigurationRegistry,
)
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
    SeverityThreshold,
)
from artemis.task_utils import get_target_host, get_target_url
from artemis.utils import (
    check_output_log_on_error,
    check_output_log_on_error_with_stderr,
)
from artemis.web_technology_identification import run_tech_detection

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")
TAGS_TO_INCLUDE = ["fuzz", "fuzzing", "dast"]

TECHNOLOGY_DETECTION_CONFIG = {"wordpress": {"tags_to_exclude": ["wordpress"]}}


def group_targets_by_missing_tech(targets: List[str], logger: logging.Logger) -> Dict[frozenset[str], List[str]]:
    """
    Groups targets by the technologies that are not detected on them.

    Returns:
        Dict[frozenset[str], List[str]]: A dictionary where keys are frozensets of tags to exclude,
        and values are lists of target URLs that share the same set of undetected technologies.
    """
    tech_results = run_tech_detection(targets, logger)
    scan_groups = collections.defaultdict(list)
    all_known_techs = {tech for tech in TECHNOLOGY_DETECTION_CONFIG.keys()}

    for target_url in targets:
        detected_techs_set = {tech.lower() for tech in tech_results.get(target_url, [])}
        known_detected_techs = set()
        for tech in all_known_techs:
            if any(tech in detected_tech for detected_tech in detected_techs_set):
                known_detected_techs.add(tech)

        undetected_techs = all_known_techs - known_detected_techs

        tags_to_exclude = set()
        for tech_name in undetected_techs:
            tags_to_exclude.update(TECHNOLOGY_DETECTION_CONFIG[tech_name]["tags_to_exclude"])

        # Use a hashable frozenset as the dictionary key
        scan_groups[frozenset(tags_to_exclude)].append(target_url)
    return scan_groups


class ScanUsing(enum.Enum):
    TEMPLATES = "templates"
    WORKFLOWS = "workflows"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class NucleiDast(ArtemisBase):
    """
    Runs Nuclei templates on URLs.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "nuclei_dast"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    batch_tasks = True
    task_max_batch_size = Config.Modules.Nuclei.NUCLEI_MAX_BATCH_SIZE

    def get_default_configuration(self) -> NucleiConfiguration:
        """
        Get the default configuration for the Nuclei module.

        Returns:
            NucleiConfiguration: Default configuration instance with:
                - severity_threshold: Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD
        """
        return NucleiConfiguration(severity_threshold=Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        with self.lock:
            templates_list_command = ["-tl", "-dast"]

            template_lists_raw: Dict[str, List[str]] = {}

            for severity in SeverityThreshold.get_severity_list(SeverityThreshold.ALL):
                template_lists_raw[severity] = (
                    check_output_log_on_error(["nuclei", "-s", severity] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                )

            self._template_lists: Dict[str, List[str]] = {}

            for name in template_lists_raw.keys():
                template_list = template_lists_raw[name]

                if Config.Modules.Nuclei.NUCLEI_CHECK_TEMPLATE_LIST:
                    if len(template_list) == 0:
                        raise RuntimeError(f"Unable to obtain Nuclei templates for list {name}")

                self._template_lists[name] = []
                for template in template_list:
                    if template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP and template.startswith(
                        "dast/vuln"
                    ):
                        self._template_lists[name].append(template)

            for key in self._template_lists:
                self.log.info(
                    "There are %d templates on list %s",
                    len(self._template_lists[key]),
                    key,
                )

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
        self,
        templates: List[str],
        targets: List[str],
        extra_nuclei_args: List[str] = [],
    ) -> List[Dict[str, Any]]:
        if not targets:
            return []

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
        for milliseconds_per_request in milliseconds_per_request_candidates:
            self.log.info(
                "Running batch of templates or workflows on %d target(s), milliseconds_per_request=%d",
                len(targets),
                milliseconds_per_request,
            )
            command = [
                "nuclei",
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
                "-dast",
            ] + additional_configuration

            if templates:
                command.extend(["-templates", ",".join(templates)])

            command.extend(["-templates", "dast/vulnerabilities/lfi/linux-lfi-fuzz.yaml"])
            if extra_nuclei_args:
                command.extend(extra_nuclei_args)

            if Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER:
                # Unfortunately, because of https://github.com/projectdiscovery/interactsh/issues/135,
                # the trailing slash matters.
                command.extend(["-interactsh-server", Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER.strip("/")])

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
        templates = []

        severity_levels = (
            self.configuration.get_severity_options()  # type: ignore
            if self.configuration
            else SeverityThreshold.get_severity_list(Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)
        )

        self.log.info("Using severity levels %s for scanning", severity_levels)

        for template_list in self._template_lists.keys():
            if template_list in SeverityThreshold.get_severity_list(SeverityThreshold.ALL):
                if template_list in severity_levels:
                    templates.extend(self._template_lists[template_list])
            else:
                templates.extend(self._template_lists[template_list])

        # Remove duplicates
        templates = list(set(templates))

        self.log.info(f"running {len(templates)} templates on {len(tasks)} hosts.")

        targets: List[str] = []
        for task in tasks:
            targets.append(get_target_url(task))

        scan_groups = group_targets_by_missing_tech(targets, self.log)
        found_targets_after_grouping = []
        for scan_group in scan_groups.values():
            found_targets_after_grouping.extend(scan_group)
        assert set(found_targets_after_grouping) == set(targets)

        findings: List[Dict[str, Any]] = []
        for tags_frozen_set, group_targets in scan_groups.items():
            extra_args = []
            if tags_frozen_set:
                self.log.info(f"For {len(group_targets)} targets, excluding tags: {tags_frozen_set}")
                extra_args = ["-etags", ",".join(tags_frozen_set)]
            else:
                self.log.info(f"For {len(group_targets)} targets, not excluding any tags")

            findings.extend(self._scan(templates, group_targets, extra_nuclei_args=extra_args))

        links_per_task = {}
        for task in tasks:
            links = self._get_links(get_target_url(task))
            # Let's scan both links with stripped query strings and with original one. We may catch a bug on either
            # of them.
            links_per_task[task.uid] = list(set(links) | set([self._strip_query_string(link) for link in links]))
            self.log.info("Links for %s: %s", get_target_url(task), links_per_task[task.uid])

        # That way, if we have 100 links for a webpage, we won't run 100 concurrent scans for that webpage
        for link_package in itertools.zip_longest(*list(links_per_task.values())):
            findings.extend(
                self._scan(
                    Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS,
                    [item for item in link_package if item],
                )
            )

        findings_per_task = collections.defaultdict(list)
        findings_unmatched = []
        for finding in findings:
            found = False
            for task in tasks:
                if "url" in finding:
                    if finding["url"] in [get_target_url(task)] + links_per_task[task.uid]:
                        findings_per_task[task.uid].append(finding)
                        found = True
                        break
                elif "matched-at" in finding:
                    urls = [get_target_url(task)] + links_per_task[task.uid]
                    hosts_with_port = [
                        urllib.parse.urlparse(item).netloc for item in urls if ":" in urllib.parse.urlparse(item).netloc
                    ]
                    if finding["matched-at"] in urls or finding["matched-at"] in hosts_with_port:
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
                    f"[{finding['info']['severity']}] {finding['url']}: {finding['info'].get('name')} {finding['info'].get('description', '')}"
                )

            if messages:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join(sorted(messages))
            else:
                status = TaskStatus.OK
                status_reason = None
            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=result)


RuntimeConfigurationRegistry().register_configuration(NucleiDast.identity, NucleiConfiguration)


if __name__ == "__main__":
    NucleiDast().loop()
