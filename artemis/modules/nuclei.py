#!/usr/bin/env python3
import collections
import json
import os
import random
import shutil
import subprocess
import urllib
from typing import Any, Callable, Dict, List

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config, SeverityThreshold
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.modules.base.configuration_registry import ConfigurationRegistry
from artemis.modules.nuclei_configuration import NucleiConfiguration
from artemis.task_utils import get_target_host, get_target_url
from artemis.utils import check_output_log_on_error

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")
TAGS_TO_INCLUDE = ["fuzz", "fuzzing", "dast"]


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

    def get_default_configuration(self) -> NucleiConfiguration:
        """
        Get the default configuration for the Nuclei module.
        
        Returns:
            NucleiConfiguration: Default configuration instance with:
                - enabled: True
                - severity_threshold: Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD
                - max_templates: None (no limit)
        """
        return NucleiConfiguration(
            enabled=True,
            severity_threshold=Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD,
            max_templates=None
        )

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        # Register the NucleiConfiguration with the registry
        registry = ConfigurationRegistry()
        registry.register_configuration(self.identity, NucleiConfiguration)
        self.log.info(f"Registered NucleiConfiguration for module {self.identity}")

        # We clone this repo in __init__ (on karton start) so that it will get periodically
        # re-cloned when the container gets retarted every 𝑛 tasks. The same logic lies behind
        # updating the Nuclei templates in __init__.
        if os.path.exists("/known-exploited-vulnerabilities/"):
            shutil.rmtree("/known-exploited-vulnerabilities/")

        subprocess.call(["git", "clone", "https://github.com/Ostorlab/KEV/", "/known-exploited-vulnerabilities/"])
        with self.lock:
            subprocess.call(["nuclei", "-update-templates"])

            templates_list_command = ["-tl", "-it", ",".join(TAGS_TO_INCLUDE)]
            
            # Get the severity levels to include based on the configured threshold
            severity_levels = SeverityThreshold.get_severity_list(Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)
            self.log.info(f"Using severity threshold: {Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD.value}, including levels: {severity_levels}")

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
            }
            
            # Add severity-based template sources based on the threshold
            for severity in severity_levels:
                template_list_sources[severity] = lambda sev=severity: check_output_log_on_error(
                    ["nuclei", "-s", sev] + templates_list_command, self.log
                ).decode("ascii").split()
            
            # Add non-severity specific sources
            if "log_exposures" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                template_list_sources["log_exposures"] = lambda: [
                    item
                    for item in check_output_log_on_error(["nuclei"] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                    if item.startswith("http/exposures/logs")
                    # we already have a git detection module that filters FPs such as
                    # exposed source code of a repo that is already public
                    and not item.startswith("http/exposures/logs/git-")
                ]
            
            if "exposed_panels" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                template_list_sources["exposed_panels"] = lambda: [
                    item
                    for item in check_output_log_on_error(["nuclei"] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                    if item.startswith(EXPOSED_PANEL_TEMPLATE_PATH_PREFIX)
                ]

            self._templates = Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES
            for name in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS:
                if name not in template_list_sources:
                    # Skip the severity-based template lists that aren't in the threshold
                    if name in ["critical", "high", "medium", "low", "info", "unknown"] and name not in severity_levels:
                        self.log.info(f"Skipping template list '{name}' due to severity threshold filter")
                        continue
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

        self._nuclei_templates_to_skip_probabilistically_set = set()
        if Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE:
            for line in open(Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE):
                self._nuclei_templates_to_skip_probabilistically_set.add(line.strip())

    def _get_links(self, url: str) -> List[str]:
        links = get_links_and_resources_on_same_domain(url)
        random.shuffle(links)

        links = links[: Config.Modules.Nuclei.NUCLEI_MAX_NUM_LINKS_TO_PROCESS]
        return links

    def _strip_query_string(self, url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    def _scan(self, templates: List[str], targets: List[str]) -> List[Dict[str, Any]]:
        if not targets:
            return []

        # Apply max_templates limit from configuration if set
        if self.configuration and self.configuration.max_templates:
            templates = templates[:self.configuration.max_templates]

        templates_filtered = []

        num_templates_skipped = 0
        for template in templates:
            if template not in self._nuclei_templates_to_skip_probabilistically_set:
                templates_filtered.append(template)
            elif (
                template in self._nuclei_templates_to_skip_probabilistically_set
                and random.uniform(0, 100)
                >= Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY
            ):
                templates_filtered.append(template)
            else:
                num_templates_skipped += 1

        self.log.info(
            "Requested to skip %d templates with probability %f, actually skipped %d",
            len(self._nuclei_templates_to_skip_probabilistically_set),
            Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_PROBABILITY,
            num_templates_skipped,
        )
        self.log.info(
            "After probabilistic skipping, executing %d templates out of %d",
            len(templates_filtered),
            len(templates),
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

        # Get severity levels from configuration
        severity_levels = (
            self.configuration.get_severity_options() 
            if self.configuration 
            else SeverityThreshold.get_severity_list(Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)
        )
        severity_param = ",".join(severity_levels)

        self.log.info("Using severity threshold: %s, including levels: %s", 
                     self.configuration.severity_threshold.value if self.configuration else "default",
                     severity_levels)

        lines = []
        for template_chunk in more_itertools.chunked(
            templates_filtered, Config.Modules.Nuclei.NUCLEI_TEMPLATE_CHUNK_SIZE
        ):
            for milliseconds_per_request in milliseconds_per_request_candidates:
                self.log.info(
                    "Running batch of %d templates on %d target(s), milliseconds_per_request=%d, with severity levels: %s",
                    len(template_chunk),
                    len(targets),
                    milliseconds_per_request,
                    severity_param,
                )
                command = [
                    "nuclei",
                    "-disable-update-check",
                    "-itags",
                    ",".join(TAGS_TO_INCLUDE),
                    "-v",
                    "-templates",
                    ",".join(template_chunk),
                    "-timeout",
                    str(Config.Limits.REQUEST_TIMEOUT_SECONDS),
                    "-jsonl",
                    "-system-resolvers",
                    "-rate-limit",
                    "1",
                    "-rate-limit-duration",
                    str(milliseconds_per_request) + "ms",
                    "-s",  # Add severity filter
                    severity_param,
                ] + additional_configuration

                if Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER:
                    command.extend(["-interactsh-server", Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER])

                # The `-it` flag will include the templates provided in NUCLEI_ADDITIONAL_TEMPLATES even if
                # they're marked with as tag such as `fuzz` which prevents them from being executed by default.
                for template in Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES:
                    if template in template_chunk:
                        command.append("-it")
                        command.append(template)

                for target in targets:
                    command.append("-target")
                    command.append(target)

                self.log.debug("Running command: %s", " ".join(command))
                call_result = check_output_log_on_error(command, self.log, capture_stderr=True)

                call_result_utf8 = call_result.decode("utf-8", errors="ignore")
                call_result_utf8_lines = call_result_utf8.split("\n")

                for line in call_result_utf8_lines:
                    if line.startswith("{"):
                        self.log.info("Found: %s...", line[:100])
                        self.log.debug("%s", line)
                        lines.append(line)

                if "context deadline exceeded" in call_result_utf8:
                    self.log.info(
                        "Detected %d occurencies of 'context deadline exceeded'",
                        call_result_utf8.count("context deadline exceeded"),
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
        tasks = [task for task in tasks if self.check_connection_to_base_url_and_save_error(task)]

        self.log.info(f"running {len(self._templates)} templates on {len(tasks)} hosts.")

        if len(tasks) == 0:
            return

        targets = []
        for task in tasks:
            targets.append(get_target_url(task))

        links_per_task = {}
        links = []
        for task in tasks:
            links = self._get_links(get_target_url(task))
            # Let's scan both links with stripped query strings and with original one. We may catch a bug on either
            # of them.
            links_per_task[task.uid] = list(set(links) | set([self._strip_query_string(link) for link in links]))
            self.log.info("Links for %s: %s", get_target_url(task), links_per_task[task.uid])
            links.extend(links_per_task[task.uid])

        findings = self._scan(self._templates, targets) + self._scan(
            Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS, links
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
