#!/usr/bin/env python3
import collections
import enum
import itertools
import json
import logging
import os
import random
import shutil
import subprocess
import time
import urllib
from statistics import StatisticsError, quantiles
from typing import Any, Dict, List

import more_itertools
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
    add_common_params_from_wordlist,
    check_output_log_on_error,
    check_output_log_on_error_with_stderr,
)
from artemis.web_technology_identification import run_tech_detection

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")
TAGS_TO_INCLUDE = ["fuzz", "fuzzing", "dast"]

TECHNOLOGY_DETECTION_CONFIG = {"wordpress": {"tags_to_exclude": ["wordpress"]}}

# It is important to keep ssrf, redirect and lfi at the top so that their params get the correct default values
DAST_SCANNING: Dict[str, Dict[str, Any]] = {
    "ssrf": {  # ssrf dast templates work only when the param is of the form http://...
        "params_wordlist": os.path.join(os.path.dirname(__file__), "data", "dast_params", "ssrf.txt"),
        "param_default_value": "http://127.0.0.1/abc.html",
    },
    "redirect": {  # redirect dast templates work only when param is of the form http://
        "params_wordlist": os.path.join(os.path.dirname(__file__), "data", "dast_params", "redirect.txt"),
        "param_default_value": "http://127.0.0.1/abc.html",
    },
    # lfi dast templates work only when the param is a filename with some extension, which is why we are using abc.html
    # also the reason why the above two templates default values end in abc.html so that it takes care in case the two wordlists
    # have any repeated values
    "lfi": {
        "params_wordlist": os.path.join(os.path.dirname(__file__), "data", "dast_params", "lfi.txt"),
        "param_default_value": "abc.html",
    },
    "cmdi": {
        "params_wordlist": os.path.join(os.path.dirname(__file__), "data", "dast_params", "cmdi.txt"),
        "param_default_value": "testing",
    },
    "sqli": {
        "params_wordlist": os.path.join(os.path.dirname(__file__), "data", "dast_params", "sqli.txt"),
        "param_default_value": "testing",
    },
    "xss": {
        "params_wordlist": os.path.join(os.path.dirname(__file__), "data", "dast_params", "xss.txt"),
        "param_default_value": "testing",
    },
}

UPDATE_INTERVAL = 60 * 60 * 24 * 7  # 7 days


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
class Nuclei(ArtemisBase):
    """
    Runs Nuclei templates on URLs.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "nuclei"
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

        # We are cloning the KEV repository and updating templates in the Dockerfile
        # so we don't need to do every time we start the module.
        kev_directory = "/known-exploited-vulnerabilities/"
        if os.path.exists(kev_directory) and os.path.getctime(kev_directory) < time.time() - UPDATE_INTERVAL:
            shutil.rmtree(kev_directory, ignore_errors=True)
            subprocess.call(["git", "clone", "https://github.com/Ostorlab/KEV/", kev_directory])

        with self.lock:
            template_directory = "/root/nuclei-templates/"
            if (
                os.path.exists(template_directory)
                and os.path.getctime(template_directory) < time.time() - UPDATE_INTERVAL
            ):
                shutil.rmtree(template_directory, ignore_errors=True)
                shutil.rmtree("/root/.config/nuclei/", ignore_errors=True)

            subprocess.call(["nuclei", "-update-templates"])

            templates_list_command = ["-tl", "-it", ",".join(TAGS_TO_INCLUDE)]

            template_lists_raw: Dict[str, List[str]] = {}

            for severity in SeverityThreshold.get_severity_list(SeverityThreshold.ALL):
                template_lists_raw[severity] = (
                    check_output_log_on_error(["nuclei", "-s", severity] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                )

            # Add non-severity specific sources
            if "known_exploited_vulnerabilities" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                template_lists_raw["known_exploited_vulnerabilities"] = [
                    item
                    for item in check_output_log_on_error(
                        ["find", "/known-exploited-vulnerabilities/nuclei/"], self.log
                    )
                    .decode("ascii")
                    .split()
                    if item.endswith(".yml") or item.endswith(".yaml")
                ]

            listed_templates = (
                check_output_log_on_error(["nuclei"] + templates_list_command, self.log).decode("ascii").split()
            )
            if "log_exposures" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                template_lists_raw["log_exposures"] = [
                    item
                    for item in listed_templates
                    if item.startswith("http/exposures/logs")
                    # we already have a git detection module that filters FPs such as
                    # exposed source code of a repo that is already public
                    and not item.startswith("http/exposures/logs/git-")
                ]

            if "exposed_panels" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                template_lists_raw["exposed_panels"] = [
                    item for item in listed_templates if item.startswith(EXPOSED_PANEL_TEMPLATE_PATH_PREFIX)
                ]

            self._template_lists: Dict[str, List[str]] = {}

            for name in template_lists_raw.keys():
                template_list = template_lists_raw[name]

                if Config.Modules.Nuclei.NUCLEI_CHECK_TEMPLATE_LIST:
                    if len(template_list) == 0:
                        raise RuntimeError(f"Unable to obtain Nuclei templates for list {name}")

                self._template_lists[name] = []
                for template in template_list:
                    if template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP:
                        self._template_lists[name].append(template)

            self._template_lists["custom"] = Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES

            dast_templates = check_output_log_on_error(["nuclei", "-dast", "-tl"], self.log).decode("ascii").split()
            dast_templates = [
                template
                for template in dast_templates
                # Skipping CSP bypass templates as it's enough to detect an XSS
                # Skipping CVEs as they're too specific to be run on every link
                if template.startswith("dast/")
                and template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP
                and "/csp-bypass/" not in template
                and "/cve" not in template
            ]
            self._dast_templates: Dict[str, List[str]] = {}
            for keyword in DAST_SCANNING.keys():
                self._dast_templates[keyword] = [template for template in dast_templates if keyword in template]
            self._dast_templates["other"] = [
                template for template in dast_templates if not any(template in s for s in self._dast_templates.values())
            ]

            for custom_template_filename in os.listdir(CUSTOM_TEMPLATES_PATH):
                self._template_lists["custom"].append(os.path.join(CUSTOM_TEMPLATES_PATH, custom_template_filename))

            for key in self._template_lists:
                self.log.info(
                    "There are %d templates on list %s",
                    len(self._template_lists[key]),
                    key,
                )

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
        self,
        templates_or_workflows: List[str],
        scan_using: ScanUsing,
        targets: List[str],
        extra_nuclei_args: List[str] = [],
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

        if not templates_or_workflows_filtered:
            self.log.info("No templates or workflows left after filtering, skipping scan.")
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
        time_start = time.time()
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

                if extra_nuclei_args:
                    command.extend(extra_nuclei_args)

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
                    # Unfortunately, because of https://github.com/projectdiscovery/interactsh/issues/135,
                    # the trailing slash matters.
                    command.extend(["-interactsh-server", Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER.strip("/")])

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
        self.log.info(
            "Scanning of %d targets (%s...) with %d templates/workflows (%s...) took %f seconds",
            len(targets),
            targets[:3],
            len(templates_or_workflows_filtered),
            templates_or_workflows_filtered[:3],
            time.time() - time_start,
        )

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

        self.log.info(f"running {len(templates)} templates and {len(self._workflows)} workflow on {len(tasks)} hosts.")

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

            findings.extend(self._scan(templates, ScanUsing.TEMPLATES, group_targets, extra_nuclei_args=extra_args))
            findings.extend(
                self._scan(self._workflows, ScanUsing.WORKFLOWS, group_targets, extra_nuclei_args=extra_args)
            )

        # DAST scanning
        dast_targets: List[str] = []
        for task in tasks:
            param_url = get_target_url(task)
            for _, template_data in DAST_SCANNING.items():
                param_url = add_common_params_from_wordlist(
                    param_url, template_data["params_wordlist"], template_data["param_default_value"]
                )
            dast_targets.append(param_url)

        # Running all dast templates at once on all dast targets constructed
        all_dast_templates = []
        for keyword in DAST_SCANNING.keys():
            all_dast_templates.extend(self._dast_templates[keyword])
        all_dast_templates.extend(self._dast_templates["other"])

        findings.extend(
            self._scan(
                all_dast_templates,
                ScanUsing.TEMPLATES,
                dast_targets,
                extra_nuclei_args=["-dast"],
            )
        )

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
                    ScanUsing.TEMPLATES,
                    [item for item in link_package if item],
                )
            )

            dast_targets.clear()

            for item in link_package:
                if item:
                    param_url = item
                    for _, template_data in DAST_SCANNING.items():
                        param_url = add_common_params_from_wordlist(
                            param_url, template_data["params_wordlist"], template_data["param_default_value"]
                        )
                    dast_targets.append(param_url)

            all_dast_templates = []
            for keyword in DAST_SCANNING.keys():
                all_dast_templates.extend(self._dast_templates[keyword])
            all_dast_templates.extend(self._dast_templates["other"])

            findings.extend(
                self._scan(
                    all_dast_templates,
                    ScanUsing.TEMPLATES,
                    dast_targets,
                    extra_nuclei_args=["-dast"],
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
                    f"[{finding['info']['severity']}] {finding['matched-at']}: {finding['info'].get('name')} {finding['info'].get('description', '')}"
                )

            if messages:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join(sorted(messages))
            else:
                status = TaskStatus.OK
                status_reason = None
            self.db.save_task_result(task=task, status=status, status_reason=status_reason, data=result)


RuntimeConfigurationRegistry().register_configuration(Nuclei.identity, NucleiConfiguration)


if __name__ == "__main__":
    Nuclei().loop()
