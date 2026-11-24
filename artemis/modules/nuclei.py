#!/usr/bin/env python3
import collections
import dataclasses
import functools
import itertools
import json
import logging
import os
import random
import shutil
import subprocess
import tempfile
import time
import traceback
import urllib
from statistics import StatisticsError, quantiles
from typing import Any, Dict, List, Optional

import more_itertools
import timeout_decorator
import yaml
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
from artemis.modules import nuclei_refuzz_templates
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.modules.nuclei_router import NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY
from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
    SeverityThreshold,
)
from artemis.reporting.modules.nuclei.poc_url_utils import (
    RefuzzError,
    align_query_pairs,
    count_query_params,
    log_not_minimized,
    minimize_nuclei_matched_at_url,
    summary_logger,
)
from artemis.task_utils import get_target_host, get_target_url
from artemis.utils import (
    CalledProcessErrorWithMessage,
    check_output_log_on_error,
    check_output_log_on_error_with_stderr,
    directory_backup,
)

EXPOSED_PANEL_TEMPLATE_PATH_PREFIX = "http/exposed-panels/"
TECHNOLOGY_TEMPLATE_PATH_PREFIX = "http/technologies/"
TECHNOLOGIES_TEMPLATE_PATH_PREFIXES = [EXPOSED_PANEL_TEMPLATE_PATH_PREFIX, TECHNOLOGY_TEMPLATE_PATH_PREFIX]

CUSTOM_TEMPLATES_PATH = os.path.join(os.path.dirname(__file__), "data/nuclei_templates_custom/")
TAGS_TO_INCLUDE = ["fuzz", "fuzzing"]
TAGS_TO_EXCLUDE = ["intrusive"]
NUCLEI_TEMPLATES_LOCATION = "/root/nuclei-templates/"


METRIC_WORK_UNITS = Counter("nuclei_work_units_total", "Total (targets x templates) processed")

METRIC_BATCH_COMMAND_DURATION = Histogram(
    "nuclei_batch_command_duration_seconds",
    "Duration per batch",
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


def _nuclei_error_category(error: str) -> str:
    for substring, name in NUCLEI_ERROR_CATEGORIES:
        if substring in error:
            return name
    return "unknown-error"


def build_common_nuclei_command() -> List[str]:
    """Return the Nuclei flags shared by every invocation Artemis makes.

    Both the batch scan (:meth:`Nuclei._scan`) and the single-URL re-fuzz used
    to shorten PoC URLs (:func:`_run_refuzz`) start from this
    list, so a re-fuzz reproduces the finding under the same conditions the
    scan found it (user agent, rate limit, timeout, resolvers, interactsh).
    Flags that only make sense for a batch (parallelism, stats, per-batch rate
    limit duration) stay in the caller.
    """
    command = [
        "nuclei",
        "-disable-update-check",
        "-timeout",
        str(Config.Limits.REQUEST_TIMEOUT_SECONDS),
        "-jsonl",
        "-system-resolvers",
        "-rate-limit",
        "1",
        "-response-size-read",
        "1048576",
    ]

    if "RUNNING_TESTS" not in os.environ:
        command.append("-restrict-local-network-access")

    if Config.Miscellaneous.CUSTOM_USER_AGENT:
        command.extend(["-H", "User-Agent: " + Config.Miscellaneous.CUSTOM_USER_AGENT])

    if Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER:
        # Unfortunately, because of https://github.com/projectdiscovery/interactsh/issues/135,
        # the trailing slash matters.
        command.extend(["-interactsh-server", Config.Modules.Nuclei.NUCLEI_INTERACTSH_SERVER.strip("/")])

    return command


def _is_dast_finding(finding: Dict[str, Any]) -> bool:
    """Whether a finding comes from a DAST template - the only ones whose
    matched-at URL carries the wordlist parameters and can be re-fuzzed with
    ``-dast``.
    """
    dast_directory = os.path.join(os.path.normpath(NUCLEI_TEMPLATES_LOCATION), "dast") + os.sep
    template = finding.get("template") or ""
    template_path = os.path.normpath(finding.get("template-path") or "")
    return template.startswith("dast/") or template_path.startswith(dast_directory)


@dataclasses.dataclass
class _RefuzzRun:
    """What one Nuclei re-fuzz returned."""

    results: List[Dict[str, Any]]
    # Requests Nuclei sent, from its trace log.
    requests: int
    # Request errors by category (as in the scan's error summary).
    errors: Dict[str, int]
    elapsed: float
    # Set instead of raising, so that the caller can log the call first.
    error: str = ""


def _run_refuzz(url: str, template_path: str, extra_args: List[str], timeout: int) -> _RefuzzRun:
    """Re-fuzz ``url`` with ``template_path`` in multiple fuzzing mode (one Nuclei process)."""
    # Batch-only flags (rate-limit-duration, bulk-size, concurrency, stats)
    # are intentionally left out of the shared command builder - they are
    # meaningless for a single-URL re-fuzz. The trace log, unlike in the
    # scan, is only parsed for the request count and the request errors.
    command = (
        build_common_nuclei_command()
        + ["-u", url, "-t", template_path, "-dast", "-fuzzing-mode", "multiple", "-silent"]
        + ["-trace-log", "/dev/stderr"]
        + extra_args
    )

    started = time.monotonic()
    error = ""
    try:
        # Nuclei reads targets from stdin whenever it is a pipe or a file, and
        # waits for it up to -input-read-timeout (3 minutes) - longer than the
        # re-fuzz timeout - if the worker's stdin is a pipe that stays open.
        process = subprocess.run(command, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout)
        stdout, stderr = process.stdout, process.stderr
        if process.returncode != 0:
            error = f"exit_code_{process.returncode}"
    except FileNotFoundError:
        stdout, stderr, error = b"", b"", "nuclei_missing"
    except subprocess.TimeoutExpired as e:
        stdout, stderr, error = e.stdout or b"", e.stderr or b"", "timeout"

    results = []
    for line in stdout.decode("utf-8", errors="ignore").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            results.append(entry)

    requests = 0
    errors: Dict[str, int] = collections.defaultdict(int)
    for line in stderr.decode("utf-8", errors="ignore").splitlines():
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and "address" in entry:
            requests += 1
            if entry.get("error") and entry["error"] != "none":
                errors[_nuclei_error_category(entry["error"])] += 1

    return _RefuzzRun(
        results=results,
        requests=requests,
        errors=dict(errors),
        elapsed=time.monotonic() - started,
        error=error,
    )


def _log_refuzz(template_id: str, call: int, url: str, label: str, run: _RefuzzRun, reproduced: bool) -> None:
    summary_logger.info(
        "PoC minimization re-fuzz: template=%s call=%d params=%d payloads=%s reproduced=%s elapsed=%.1fs "
        "requests=%d request_errors=%s%s",
        template_id,
        call,
        count_query_params(url),
        label,
        "yes" if reproduced else ("error" if run.error else "no"),
        run.elapsed,
        run.requests,
        ",".join(f"{category}:{count}" for category, count in sorted(run.errors.items())) or "none",
        f" error={run.error}" if run.error else "",
    )


def _log_unexpected_error(finding: Dict[str, Any], error: Exception) -> None:
    # The type and the place only: the message may carry the URL. The place
    # is the last frame in Artemis's own code, if any.
    frames = list(traceback.extract_tb(error.__traceback__))
    frames = [frame for frame in frames if "/artemis/" in frame.filename.replace(os.sep, "/")] or frames
    where = f"{os.path.basename(frames[-1].filename)}:{frames[-1].lineno}" if frames else "unknown"
    summary_logger.warning("PoC minimization failed: %s at %s", type(error).__name__, where)
    log_not_minimized(
        str(finding["matched-at"]),
        str(finding.get("template-id")),
        "fallback_error",
        error=f"unexpected_{type(error).__name__}",
    )


@functools.lru_cache(maxsize=256)
def _load_template_at(template_path: str, mtime: float) -> Optional[Dict[str, Any]]:
    try:
        return nuclei_refuzz_templates.load_template(template_path)
    except (OSError, ValueError, yaml.YAMLError):
        return None


def _load_template_cached(template_path: str) -> Optional[Dict[str, Any]]:
    # Keyed by the modification time too, as the templates get updated.
    try:
        mtime = os.path.getmtime(template_path)
    except OSError:
        return None
    return _load_template_at(template_path, mtime)


class _InBandReproducer:
    """``reproduces_fn`` for DAST findings: whether Nuclei, in multiple
    fuzzing mode, still reports the finding on a URL."""

    def __init__(self, template_path: str, template_id: str, finding: Dict[str, Any], workdir: str) -> None:
        self.template_path = template_path
        self.template_id = template_id
        self.workdir = workdir
        self.calls = 0
        self.narrowed_path: Optional[str] = None
        self.narrowed_without_interactsh = False
        self.narrowing = "none"
        self.payloads = "all"
        self.template = _load_template_cached(template_path)
        self.payload_set = nuclei_refuzz_templates.payload_set(self.template) if self.template is not None else None
        self.full_without_interactsh = self.template is not None and not nuclei_refuzz_templates.needs_interactsh(
            self.template
        )
        if self.template is None:
            self.narrowing = "template_unreadable"
            return

        aligned = align_query_pairs(finding.get("url") or "", finding["matched-at"]) if finding.get("url") else None
        if aligned is None:
            # Without the URL Nuclei fuzzed, the payload cannot be read off
            # the finding (bisection still works).
            self.narrowing = "url_not_aligned"
            return

        match = nuclei_refuzz_templates.find_matching_payloads(self.template, aligned)
        if match is None:
            self.narrowing = "payload_not_identified"
            return
        _, entries, _ = match
        if self._narrow(entries, "narrowed"):
            self.narrowing = "narrowed"

    def _narrow(self, entries: List[str], name: str) -> bool:
        """Use a copy of the template with only ``entries`` from now on."""
        assert self.template is not None and self.payload_set is not None
        narrowed = nuclei_refuzz_templates.with_payloads(self.template, self.payload_set[0], entries)
        try:
            self.narrowed_path = nuclei_refuzz_templates.write_template(narrowed, self.workdir, name)
        except OSError:
            self.narrowing = "write_failed"
            self.narrowed_path = None
            return False
        self.narrowed_without_interactsh = not nuclei_refuzz_templates.needs_interactsh(narrowed)
        self.payloads = f"{len(entries)}/{len(self.payload_set[1])}"
        return True

    def _check(self, url: str, template_path: str, without_interactsh: bool, label: str) -> bool:
        run = _run_refuzz(
            url,
            template_path,
            # -ni only for templates that do not send OAST URLs: response-ssrf
            # is in-band, but needs a real interactsh URL to fetch.
            ["-ni"] if without_interactsh else [],
            Config.Modules.Nuclei.NUCLEI_REFUZZ_TIMEOUT_SECONDS,
        )
        reproduced = bool(run.results)
        _log_refuzz(self.template_id, self.calls, url, label, run, reproduced)
        # A finding reported before the timeout still counts.
        if run.error and not reproduced:
            raise RefuzzError(run.error)
        return reproduced

    def _bisect(self, url: str) -> bool:
        """Narrow the template to one payload that fires on ``url``, the full
        URL; whether there is one."""
        assert self.payload_set is not None
        candidates = list(dict.fromkeys(self.payload_set[1]))
        confirmed = False
        while len(candidates) > 1:
            half = candidates[: len(candidates) // 2]
            if not self._narrow(half, f"bisect{len(half)}"):
                return False
            assert self.narrowed_path is not None
            if self._check(url, self.narrowed_path, self.narrowed_without_interactsh, f"bisect:{self.payloads}"):
                candidates, confirmed = half, True
            else:
                # Some payload fired in the scan, so it is in the other half -
                # unless the target stopped reproducing, which the check of
                # the last candidate shows.
                candidates, confirmed = candidates[len(half) :], False
        if not self._narrow(candidates, "bisected"):
            return False
        assert self.narrowed_path is not None
        if not confirmed and not self._check(url, self.narrowed_path, self.narrowed_without_interactsh, self.payloads):
            self.narrowed_path = None
            return False
        self.narrowing = "bisected"
        return True

    def __call__(self, url: str) -> bool:
        self.calls += 1
        if self.calls == 1:
            # The first check is on the full URL, which the scan has just
            # reported.
            if self.narrowed_path is not None:
                if self._check(url, self.narrowed_path, self.narrowed_without_interactsh, self.payloads):
                    return True
                # The payload was misidentified.
                self.narrowed_path = None
                self.narrowing = "rejected"
            if self.payload_set is not None and len(set(self.payload_set[1])) > 1 and self._bisect(url):
                return True
            # No single payload found to fire: the whole template decides.
            self.narrowed_path = None
            self.payloads = "all"

        if self.narrowed_path is None:
            return self._check(url, self.template_path, self.full_without_interactsh, "all")
        return self._check(url, self.narrowed_path, self.narrowed_without_interactsh, self.payloads)

    def describe(self) -> str:
        return f"narrowing={self.narrowing} payloads={self.payloads}"


def _minimize_dast_finding(finding: Dict[str, Any]) -> str:
    """Return the shortened matched-at URL of a DAST finding, or the original."""
    try:
        return _minimize_dast_poc(finding)
    except timeout_decorator.TimeoutError:
        # module_base's task timeout, raised wherever the batch happens to be
        # (an Exception too): it must end the batch, not just this minimization.
        raise
    except Exception as e:
        # A bug here must not lose the finding - nor the whole batch, which
        # run_multiple would fail with it.
        _log_unexpected_error(finding, e)
        return str(finding["matched-at"])


def _minimize_dast_poc(finding: Dict[str, Any]) -> str:
    template_path = finding.get("template-path") or os.path.join(
        NUCLEI_TEMPLATES_LOCATION, finding.get("template") or finding["template-id"]
    )
    template_id = finding["template-id"]

    with tempfile.TemporaryDirectory(prefix="artemis-poc-refuzz-") as workdir:
        reproducer = _InBandReproducer(template_path, template_id, finding, workdir)
        return minimize_nuclei_matched_at_url(
            finding["matched-at"],
            reproduces_fn=reproducer,
            template_id=template_id,
            max_refuzz_calls=Config.Modules.Nuclei.NUCLEI_REFUZZ_MAX_CALLS_PER_FINDING,
            base_url=finding.get("url"),
            describe_fn=reproducer.describe,
        )


UPDATE_INTERVAL = 60 * 60 * 24 * 7  # 7 days


def get_max_num_parameters(targets: List[str]) -> int:
    if not targets:
        return 0

    return max([len(urllib.parse.parse_qs(urllib.parse.urlparse(item).query)) for item in targets])


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
                "requests_per_second_override": self._get_requests_per_second_batch_key(task),
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

            templates_list_command = ["-tl", "-it", ",".join(TAGS_TO_INCLUDE), "-etags", ",".join(TAGS_TO_EXCLUDE)]

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

            # Support also the obsolete `exposed_panels` name or the new one
            if (
                "exposed_panels" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS
                or "technologies" in Config.Modules.Nuclei.NUCLEI_TEMPLATE_LISTS
            ):
                template_lists_raw["technologies"] = [
                    item
                    for item in listed_templates
                    if any(item.startswith(prefix) for prefix in TECHNOLOGIES_TEMPLATE_PATH_PREFIXES)
                    and not (item.startswith(TECHNOLOGY_TEMPLATE_PATH_PREFIX) and "/wordpress/" in item)
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

        self._nuclei_templates_to_skip_probabilistically_set = set()
        if Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE:
            with open(Config.Modules.Nuclei.NUCLEI_TEMPLATES_TO_SKIP_PROBABILISTICALLY_FILE, encoding="utf-8") as f:
                for line in f:
                    self._nuclei_templates_to_skip_probabilistically_set.add(line.strip())

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
        error_counts: Dict[str, int] = collections.defaultdict(int)
        context_deadline_exceeded_targets: Dict[str, int] = collections.defaultdict(int)
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
            error_counts[_nuclei_error_category(error)] += 1

            if "context deadline exceeded" in error:
                # Aggregate per target, not per template path. A single unreachable or slow
                # target times out for every template path it's hit with, so the actionable
                # signal - and the value the eventual re-run would pass back to Nuclei via
                # `-target` - is the target, not the path. `input` carries the requested
                # host:port (matching `-target`); `address` is the resolved IP and is used only
                # as a fallback when `input` is absent.
                page = entry.get("input")
                if page:
                    target = urllib.parse.urlparse(page).netloc or page
                else:
                    target = entry.get("address")
                if target:
                    context_deadline_exceeded_targets[target] += 1

        if not error_counts:
            return

        self.log.info(
            "Nuclei request error summary: %s",
            dict(error_counts),
        )

        if context_deadline_exceeded_targets:
            self.log.info(
                "Targets that caused 'context deadline exceeded': %d distinct target(s): %s",
                len(context_deadline_exceeded_targets),
                dict(context_deadline_exceeded_targets),
            )

    def _scan(
        self,
        templates: List[str],
        targets: List[str],
        use_fake_home: bool = False,
        extra_nuclei_args: List[str] = [],
    ) -> List[Dict[str, Any]]:
        if not targets:
            return []

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

        if not templates_filtered:
            self.log.info("No templates left after filtering, skipping scan.")
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

        lines = []
        time_start = time.time()
        for chunk in more_itertools.chunked(templates_filtered, Config.Modules.Nuclei.NUCLEI_CHUNK_SIZE):
            for milliseconds_per_request in milliseconds_per_request_candidates:
                self.log.info(
                    "Running batch of %d templates on %d target(s), milliseconds_per_request=%d",
                    len(chunk),
                    len(targets),
                    milliseconds_per_request,
                )
                command = build_common_nuclei_command() + [
                    "-v",
                    "-rate-limit-duration",
                    str(milliseconds_per_request) + "ms",
                    "-templates",
                    ",".join(chunk),
                    "-stats-json",
                    "-stats-interval",
                    "1",
                    "-concurrency",
                    "5",
                    "-bulk-size",
                    str(len(targets)),
                    "-trace-log",
                    "/dev/stderr",
                ]

                if extra_nuclei_args:
                    command.extend(extra_nuclei_args)

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

                METRIC_BATCH_COMMAND_DURATION.observe(time.time() - command_start_time)

                units = len(targets) * len(chunk)
                METRIC_WORK_UNITS.inc(units)

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
        METRIC_SCAN_DURATION.observe(scan_duration)
        self.log.info(
            "Scanning of %d targets (%s...) with %d templates (%s...) took %f seconds",
            len(targets),
            targets[:3],
            len(templates_filtered),
            templates_filtered[:3],
            scan_duration,
        )

        return findings

    def run_multiple(self, tasks: List[Task]) -> None:
        scan_tag_args = ["-itags", ",".join(TAGS_TO_INCLUDE), "-etags", ",".join(TAGS_TO_EXCLUDE)]
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

        self.log.info(f"running {len(templates)} templates on {len(tasks)} hosts.")

        targets: List[str] = []
        for task in tasks:
            targets.append(get_target_url(task))

        findings = self._scan(templates, targets, extra_nuclei_args=scan_tag_args)

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
                # Only DAST findings carry the wordlist parameters worth shortening.
                if "matched-at" in finding and _is_dast_finding(finding):
                    finding["matched-at"] = _minimize_dast_finding(finding)
                result.append(finding)
                messages.append(
                    f"[{finding['info']['severity']}] {finding.get('matched-at', None) or finding.get('url')}: {finding['info'].get('name')} {finding['info'].get('description', '')}"
                )

            if messages:
                status = TaskStatus.INTERESTING
                # A template without stop-at-first-match reports one finding per matching payload, and
                # those render as identical lines. Show each line once; the findings stay intact in `data`.
                status_reason = ", ".join(sorted(set(messages)))
            else:
                status = TaskStatus.OK
                status_reason = None
            self.save_task_result(task=task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    start_http_server(9001)
    Nuclei.parallel_loop()
