#!/usr/bin/env python3
import collections
import enum
import functools
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
from typing import Any, Dict, List, Set

import more_itertools
from karton.core import Task
from prometheus_client import Counter, Histogram, start_http_server

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import (
    add_injectable_params_and_common_params_from_wordlist,
    crawl_and_filter,
)
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.modules.nuclei_router import NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY
from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
    SeverityThreshold,
)
from artemis.reporting.modules.nuclei.poc_url_utils import (
    minimize_nuclei_matched_at_url,
)
from artemis.task_utils import get_target_host, get_target_url
from artemis.utils import (
    CalledProcessErrorWithMessage,
    check_output_log_on_error,
    check_output_log_on_error_with_stderr,
    directory_backup,
)

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")
TAGS_TO_INCLUDE = ["fuzz", "fuzzing"]
NUCLEI_TEMPLATES_LOCATION = "/root/nuclei-templates/"


METRIC_WORK_UNITS = Counter("nuclei_work_units_total", "Total (targets x templates) processed", ["scan_type"])

METRIC_BATCH_COMMAND_DURATION = Histogram(
    "nuclei_batch_command_duration_seconds",
    "Duration per batch",
    ["scan_type"],
    buckets=(
        1,
        2,
        5,
        10,
        30,
        60,
        120,
        180,
        240,
        300,
        600,
        900,
        1200,
        1800,
        3600,
        7200,
        14400,
        28800,
    ),
)

METRIC_SCAN_DURATION = Histogram(
    "nuclei_scan_duration_seconds",
    "Duration per scan",
    ["scan_type"],
    buckets=(
        1,
        2,
        5,
        10,
        30,
        60,
        120,
        180,
        240,
        300,
        600,
        900,
        1200,
        1800,
        3600,
        7200,
        14400,
        28800,
    ),
)


logger = logging.getLogger(__name__)


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


@functools.lru_cache(maxsize=1)
def _get_dast_param_defaults() -> Dict[str, str]:
    """Map each DAST wordlist parameter name to its default value.

    Used to rebuild a re-fuzz target: parameters that Artemis injected are
    reset to their family default (so Nuclei re-fuzzes them from a clean base,
    exactly like the original scan did), rather than being left carrying the
    payload from the multiple-mode hit. If a name appears in several wordlists,
    the first family wins (DAST_SCANNING order keeps ssrf/redirect/lfi on top).
    """
    defaults: Dict[str, str] = {}
    for template_data in DAST_SCANNING.values():
        default_value = template_data["param_default_value"]
        with open(template_data["params_wordlist"], "r") as wordlist_file:
            for line in wordlist_file:
                name = line.strip()
                if name and not name.startswith("#") and name not in defaults:
                    defaults[name] = default_value
    return defaults


def _refuzz_single_with_nuclei(url: str, template_path: str) -> Set[str]:
    """Re-run Nuclei in single fuzzing mode and return the set of parameter
    names that trigger the finding on their own.

    Injected (wordlist) parameters are reset to their default value so Nuclei
    fuzzes them from a clean base; the site's own parameters (not in any
    wordlist) keep their matched-at value. Returns an empty set on any failure
    (binary missing, timeout, no hit) - the caller then falls back to the full
    PoC.
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return set()

    defaults = _get_dast_param_defaults()

    rebuilt_pairs = []
    for raw_pair in parsed.query.split("&"):
        if not raw_pair:
            continue
        raw_name = raw_pair.split("=", 1)[0]
        name = urllib.parse.unquote_plus(raw_name)
        if name in defaults:
            rebuilt_pairs.append(raw_name + "=" + urllib.parse.quote(defaults[name], safe="/:@!$&'()*+,;="))
        else:
            rebuilt_pairs.append(raw_pair)
    refuzz_url = urllib.parse.urlunparse(parsed._replace(query="&".join(rebuilt_pairs)))

    # These flags mirror the main scan's command (_scan) so the re-fuzz
    # reproduces the finding under the same conditions (user agent, rate
    # limit, timeout, resolvers). Batch-only flags are intentionally
    # omitted: rate-limit-duration/bulk-size/concurrency/stats are
    # meaningless for a single-URL re-fuzz. Sharing a common command
    # builder with _scan is a planned follow-up (see PR description).
    try:
        command = [
            "nuclei",
            "-disable-update-check",
            "-u",
            refuzz_url,
            "-t",
            template_path,
            "-dast",
            "-fuzzing-mode",
            "single",
            "-jsonl",
            "-silent",
            "-timeout",
            str(Config.Limits.REQUEST_TIMEOUT_SECONDS),
            "-system-resolvers",
            "-rate-limit",
            "1",
            "-response-size-read",
            "1048576",
        ]
        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            command.extend(["-H", "User-Agent: " + Config.Miscellaneous.CUSTOM_USER_AGENT])
        if Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER:
            command.extend(["-interactsh-server", Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER.strip("/")])

        result = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        confirmed: Set[str] = set()
        for line in result.strip().splitlines():
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            # NOTE: assumes single-mode hits carry a non-empty "fuzzing_parameter";
            # verify against live Nuclei output.
            param = hit.get("fuzzing_parameter")
            if param:
                confirmed.add(param)
        return confirmed
    except FileNotFoundError:
        logger.warning("Nuclei binary not found, skipping URL minimization")
        return set()
    except subprocess.CalledProcessError as e:
        logger.warning("Nuclei single-mode re-fuzz failed on %s: %s", url, e)
        return set()


UPDATE_INTERVAL = 60 * 60 * 24 * 7  # 7 days


def get_max_num_parameters(targets: List[str]) -> int:
    if not targets:
        return 0

    return max([len(urllib.parse.parse_qs(urllib.parse.urlparse(item).query)) for item in targets])


class ScanUsing(enum.Enum):
    TEMPLATES = "templates"
    WORKFLOWS = "workflows"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class Nuclei(ArtemisBase):
    """
    Runs Nuclei templates on URLs. To use Nuclei, enable both nuclei-module and nuclei-router modules.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "nuclei-module"
    filters = [
        {"type": TaskType.NUCLEI_TARGET.value},
    ]

    batch_tasks = True
    task_max_batch_size = Config.Modules.Nuclei.NUCLEI_MAX_BATCH_SIZE

    def _get_nuclei_router_flags(self, tasks: list[Task]) -> list[str]:
        if len(tasks) == 0:
            return []
        first_task_flags = tasks[0].payload.get(NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY, [])
        if not isinstance(first_task_flags, list):
            return []

        if any(task.payload.get(NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY, []) != first_task_flags for task in tasks[1:]):
            self.log.warning("Nuclei picked up tasks from different groups")
            return []

        return [item for item in first_task_flags if isinstance(item, str)]

    def get_default_configuration(self) -> NucleiConfiguration:
        """
        Get the default configuration for the Nuclei module.

        Returns:
            NucleiConfiguration: Default configuration instance with:
                - severity_threshold: Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD
        """
        return NucleiConfiguration(severity_threshold=Config.Modules.Nuclei.NUCLEI_SEVERITY_THRESHOLD)

    def get_runtime_configuration(self, task: Task) -> NucleiConfiguration:
        configuration = self.get_default_configuration()

        runtime_configurations = task.payload_persistent.get("module_runtime_configurations", {})
        # FIXME: migration fallback logic to previous identity
        config_dict = runtime_configurations.get(self.identity) or runtime_configurations.get("nuclei")
        if config_dict is None:
            return configuration
        try:
            configuration = NucleiConfiguration.deserialize(config_dict)
            if not configuration.validate():
                raise ValueError(f"Invalid configuration for module {self.identity}")
        except (KeyError, TypeError, ValueError) as exc:
            self.log.warning(f"Failed to load configuration from task payload: {exc}")
            return self.get_default_configuration()
        return configuration

    def get_batch_group_key(self, task: Task) -> str | None:
        router_flags = self._get_nuclei_router_flags([task])
        configuration = self.get_runtime_configuration(task)
        return json.dumps(
            {
                "nuclei_router_flags": router_flags,
                "configuration_runtime": configuration.serialize(),
            },
            sort_keys=True,
        )

    def _should_scan_template(self, template: str) -> bool:
        if Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN:
            return template in Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN
        return template not in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        # We are cloning the KEV repository and updating templates in the Dockerfile
        # so we don't need to do every time we start the module.
        kev_directory = "/known-exploited-vulnerabilities/"
        if os.path.exists(kev_directory) and os.path.getctime(kev_directory) < time.time() - UPDATE_INTERVAL:
            try:
                with directory_backup(kev_directory, logger=self.log):
                    shutil.rmtree(kev_directory, ignore_errors=True)
                    subprocess.check_call(["git", "clone", "https://github.com/Ostorlab/KEV/", kev_directory])
            except subprocess.CalledProcessError:
                self.log.error("Failed to clone KEV repository, restored previous version")

        with self.lock:
            template_directory = "/root/nuclei-templates/"
            nuclei_config_directory = "/root/.config/nuclei/"
            if (
                os.path.exists(template_directory)
                and os.path.getctime(template_directory) < time.time() - UPDATE_INTERVAL
            ):
                try:
                    with directory_backup(template_directory, nuclei_config_directory, logger=self.log):
                        shutil.rmtree(template_directory, ignore_errors=True)
                        shutil.rmtree(nuclei_config_directory, ignore_errors=True)
                        subprocess.check_call(["nuclei", "-update-templates"])
                except subprocess.CalledProcessError:
                    self.log.error("Failed to update nuclei templates, restored previous version")
            else:
                try:
                    subprocess.check_call(["nuclei", "-update-templates"])
                except subprocess.CalledProcessError:
                    self.log.error("Failed to update nuclei templates")

            templates_list_command = ["-tl", "-it", ",".join(TAGS_TO_INCLUDE)]

            template_lists_raw: Dict[str, List[str]] = {}

            for severity in SeverityThreshold.get_severity_list(SeverityThreshold.ALL):
                template_lists_raw[severity] = [
                    item
                    for item in check_output_log_on_error(["nuclei", "-s", severity] + templates_list_command, self.log)
                    .decode("ascii")
                    .split()
                    if item.endswith(".yml") or item.endswith(".yaml")
                ]

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
                    if self._should_scan_template(template):
                        self._template_lists[name].append(template)

            self._template_lists["custom"] = Config.Modules.Nuclei.NUCLEI_ADDITIONAL_TEMPLATES

            dast_templates = check_output_log_on_error(["nuclei", "-dast", "-tl"], self.log).decode("ascii").split()
            dast_templates = [
                template
                for template in dast_templates
                # Skipping CSP bypass templates as it's enough to detect an XSS
                # Skipping CVEs as they're too specific to be run on every link
                if template.startswith("dast/")
                and self._should_scan_template(template)
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
            with open(Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE, encoding="utf-8") as f:
                for line in f:
                    self._nuclei_templates_or_workflows_to_skip_probabilistically_set.add(line.strip())

    def _get_links(self, url: str) -> List[str]:
        links = crawl_and_filter(url)

        links = [
            link
            for link in links
            if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
        ]

        return links

    def _strip_query_string(self, url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    def _get_requests_per_second_statistics(self, stderr_lines: List[str]) -> str:
        current_second_host_requests: Dict[str, int] = collections.defaultdict(int)
        requests_per_second_per_host: List[int] = []

        def _finish_current_second() -> None:
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

        return (
            "Max requests per second for a single host: %s, 75 percentile %s, 95 percentile %s, 99 percentile %s, number of hosts with rps exceeding 1 %s"
            % (
                max(requests_per_second_per_host) if requests_per_second_per_host else None,
                requests_per_second_per_host_75_percentile,
                requests_per_second_per_host_95_percentile,
                requests_per_second_per_host_99_percentile,
                sum(1 for x in requests_per_second_per_host if x > 1),
            )
        )

    def _log_nuclei_error_summary(self, lines: List[str]) -> None:
        # Error message substrings from https://github.com/projectdiscovery/utils/blob/main/errkit/kind.go
        NUCLEI_ERROR_CATEGORIES = [
            ("port closed or filtered", "port_closed_or_filtered"),
            ("connect: connection refused", "connection_refused"),
            ("no such host", "no_such_host"),
            ("no address found", "no_address_found"),
            ("could not resolve host", "could_not_resolve_host"),
            ("host unreachable", "host_unreachable"),
            ("Unable to connect", "unable_to_connect"),
            ("Client.Timeout exceeded while awaiting headers", "timeout_awaiting_headers"),
            ("context deadline exceeded", "context_deadline_exceeded"),
            ("i/o timeout", "io_timeout"),
        ]

        error_counts: Dict[str, int] = collections.defaultdict(int)
        for line in lines:
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            error = entry.get("error", "none")
            if not error or error == "none":
                continue
            category = "unknown-error"
            for substring, name in NUCLEI_ERROR_CATEGORIES:
                if substring in error:
                    category = name
                    break
            error_counts[category] += 1

        if not error_counts:
            return

        self.log.info(
            "Nuclei request error summary: %s",
            dict(error_counts),
        )

    def _scan(
        self,
        templates_or_workflows: List[str],
        scan_using: ScanUsing,
        targets: List[str],
        use_fake_home: bool = False,
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

        milliseconds_per_request_retry = int(
            max(
                1000 * Config.Modules.Nuclei.NUCLEI_SECONDS_PER_REQUEST_ON_RETRY,
                milliseconds_per_request_initial * 2,
            )
        )

        max_seconds_per_request_on_retry = Config.Modules.Nuclei.NUCLEI_MAX_SECONDS_PER_REQUEST_ON_RETRY
        if max_seconds_per_request_on_retry > 0:
            milliseconds_per_request_retry = min(
                milliseconds_per_request_retry, int(1000 * max_seconds_per_request_on_retry)
            )

        milliseconds_per_request_candidates = [milliseconds_per_request_initial, milliseconds_per_request_retry]

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
                    "-response-size-read",
                    "1048576",
                    "-concurrency",
                    "5",
                    "-bulk-size",
                    str(len(targets)),
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

                env = os.environ.copy()

                if use_fake_home:
                    # That way Nuclei will only load the specified templates, not all in /root/nuclei-templates/,
                    # which will be way faster for small template lists on some installations where IO is slow.
                    os.makedirs("/fake-home/nuclei-templates", exist_ok=True)
                    env["HOME"] = "/fake-home/"

                command_start_time = time.time()
                try:
                    stdout, stderr = check_output_log_on_error_with_stderr(command, self.log, env=env)
                except CalledProcessErrorWithMessage:
                    self.log.exception("Exception while running Nuclei")
                    # We pass to the next chunk as e.g. Nuclei raises when the templates list is empty, i.e. all
                    # are skipped.
                    break

                METRIC_BATCH_COMMAND_DURATION.labels(scan_type=scan_using).observe(time.time() - command_start_time)

                units = len(targets) * len(chunk)
                METRIC_WORK_UNITS.labels(scan_type=scan_using).inc(units)

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
                self._log_nuclei_error_summary(stderr_utf8_lines)

                if "context deadline exceeded" in stdout_utf8 + stderr_utf8:
                    self.log.info(
                        "Detected %d occurencies of 'context deadline exceeded' for %d milisecond_per_request.",
                        (stdout_utf8 + stderr_utf8).count("context deadline exceeded"),
                        milliseconds_per_request,
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
                    self.log.info(
                        "Detected 0 occurencies of 'context deadline exceeded' for %d milisecond_per_request.",
                        milliseconds_per_request,
                    )
                    break

        findings = []
        for line in lines:
            if line.strip():
                finding = json.loads(line)
                if "template-path" in finding and finding["template-path"].startswith(NUCLEI_TEMPLATES_LOCATION):
                    finding["template"] = finding["template-path"][len(NUCLEI_TEMPLATES_LOCATION) :]

                findings.append(finding)
        scan_duration = time.time() - time_start
        METRIC_SCAN_DURATION.labels(scan_type=scan_using).observe(scan_duration)
        self.log.info(
            "Scanning of %d targets (%s...) with %d templates/workflows (%s...) took %f seconds",
            len(targets),
            targets[:3],
            len(templates_or_workflows_filtered),
            templates_or_workflows_filtered[:3],
            scan_duration,
        )

        return findings

    def run_multiple(self, tasks: List[Task]) -> None:
        scan_tag_args = ["-itags", ",".join(TAGS_TO_INCLUDE)]
        router_flags = self._get_nuclei_router_flags(tasks)
        scan_tag_args.extend(router_flags)

        self.log.info("Using router flags: %s", router_flags)

        templates = []
        configuration = self.get_runtime_configuration(tasks[0])

        severity_levels = configuration.get_severity_options()

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

        findings = self._scan(templates, ScanUsing.TEMPLATES, targets, extra_nuclei_args=scan_tag_args)
        findings.extend(self._scan(self._workflows, ScanUsing.WORKFLOWS, targets, extra_nuclei_args=scan_tag_args))

        # DAST scanning
        dast_targets: List[str] = []
        for task in tasks:
            param_url = get_target_url(task)
            for _, template_data in DAST_SCANNING.items():
                param_url = add_injectable_params_and_common_params_from_wordlist(
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
                [NUCLEI_TEMPLATES_LOCATION + item for item in all_dast_templates],
                ScanUsing.TEMPLATES,
                dast_targets,
                use_fake_home=True,
                extra_nuclei_args=[
                    "-dast",
                    "-fuzzing-mode",
                    "multiple",
                    "-fuzz-param-frequency",
                    str(get_max_num_parameters(dast_targets)),
                ],
            )
        )

        links_per_task = {}
        for task in tasks:
            links = self._get_links(get_target_url(task))
            # Let's scan both links with stripped query strings and with original one. We may catch a bug on either
            # of them.
            links = list(set(links) | set([self._strip_query_string(link) for link in links]))

            random.shuffle(links)
            links = links[: Config.Modules.Nuclei.NUCLEI_MAX_NUM_LINKS_TO_PROCESS]

            links_per_task[task.uid] = links
            self.log.info("Links for %s: %s", get_target_url(task), links_per_task[task.uid])

        # That way, if we have 20 links for a webpage, we won't run 100 concurrent scans for that webpage
        for link_package in itertools.zip_longest(*list(links_per_task.values())):
            findings.extend(
                self._scan(
                    [
                        NUCLEI_TEMPLATES_LOCATION + item
                        for item in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS
                        if not item.startswith("dast/")
                    ],
                    ScanUsing.TEMPLATES,
                    [item for item in link_package if item],
                    extra_nuclei_args=scan_tag_args,
                )
            )

            dast_targets.clear()

            for item in link_package:
                if item:
                    param_url = item
                    for _, template_data in DAST_SCANNING.items():
                        param_url = add_injectable_params_and_common_params_from_wordlist(
                            param_url, template_data["params_wordlist"], template_data["param_default_value"]
                        )
                    dast_targets.append(param_url)

            findings.extend(
                self._scan(
                    [
                        NUCLEI_TEMPLATES_LOCATION + template
                        for template in Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_RUN_ON_HOMEPAGE_LINKS
                        if template.startswith("dast/")
                    ],
                    ScanUsing.TEMPLATES,
                    dast_targets,
                    use_fake_home=True,
                    extra_nuclei_args=[
                        "-dast",
                        "-fuzzing-mode",
                        "multiple",
                        "-fuzz-param-frequency",
                        str(get_max_num_parameters(dast_targets)),
                    ],
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
                    if finding.get("host", "").split(":")[0] == get_target_host(task).split(":")[0]:
                        findings_per_task[task.uid].append(finding)
                        found = True
                        break
                assert found, "Cannot match finding: %s" % finding

        for task in tasks:
            result = []
            messages = []

            for finding in findings_per_task[task.uid]:
                if "matched-at" in finding:
                    template_path = finding.get(
                        "template-path",
                        os.path.join(NUCLEI_TEMPLATES_LOCATION, finding["template-id"]),
                    )
                    finding["matched-at"] = minimize_nuclei_matched_at_url(
                        finding["matched-at"],
                        refuzz_fn=lambda url: _refuzz_single_with_nuclei(url, template_path),
                    )
                result.append(finding)
                messages.append(
                    f"[{finding['info']['severity']}] {finding.get('matched-at', None) or finding.get('url')}: {finding['info'].get('name')} {finding['info'].get('description', '')}"
                )

            if messages:
                status = TaskStatus.INTERESTING
                status_reason = ", ".join(sorted(messages))
            else:
                status = TaskStatus.OK
                status_reason = None
            self.save_task_result(task=task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    start_http_server(9001)
    Nuclei.parallel_loop()
