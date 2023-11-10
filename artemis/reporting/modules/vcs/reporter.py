import os
import sqlite3
import subprocess
import tempfile
import urllib.parse
from typing import Any, Dict, List

from artemis import config, utils
from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import cached_get, get_target_url, get_top_level_target

logger = utils.build_logger(__name__)


class VCSReporter(Reporter):
    EXPOSED_VERSION_CONTROL_FOLDER = ReportType("exposed_version_control_folder")
    EXPOSED_VERSION_CONTROL_FOLDER_WITH_CREDENTIALS = ReportType("exposed_version_control_folder_with_credentials")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "vcs":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        assert not (
            task_result["result"]["svn"] and task_result["result"]["git"]
        ), "Found a suspicious case where both correct SVN and Git repositories are present."

        if task_result["result"]["svn"]:
            return VCSReporter._create_reports_svn(task_result, language)

        if task_result["result"]["git"]:
            return VCSReporter._create_reports_git(task_result, language)

        return []

    @staticmethod
    def _create_reports_svn(task_result: Dict[str, Any], language: Language) -> List[Report]:
        repo_url = urllib.parse.urljoin(get_target_url(task_result), ".svn/")

        db_url = urllib.parse.urljoin(repo_url, "wc.db")

        logger.info("Analysing SVN folder in %s", repo_url)
        try:
            with tempfile.NamedTemporaryFile() as f:
                data = cached_get(db_url, max_size=config.Config.Modules.VCS.VCS_MAX_DB_SIZE_BYTES).content_bytes

                f.write(data)
                f.flush()
                os.fsync(f.fileno())

                con = sqlite3.connect(f.name)
                cur = con.cursor()
                cur.execute("select root from REPOSITORY")
                (remote_url,) = cur.fetchone()
        except Exception:
            logger.exception("Unable to obtain repository remote url for %s", repo_url)
            return []

        if remote_url.startswith("http://") or remote_url.startswith("https://"):
            parsed_remote_url = urllib.parse.urlparse(remote_url)
            if parsed_remote_url.password:
                return [
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=db_url,
                        report_type=VCSReporter.EXPOSED_VERSION_CONTROL_FOLDER_WITH_CREDENTIALS,
                        additional_data={
                            "username": parsed_remote_url.username,
                            "password_prefix": parsed_remote_url.password[:3],
                        },
                        timestamp=task_result["created_at"],
                    )
                ]

        logger.info("Successfully obtained remote url: %s", remote_url)

        try:
            with tempfile.TemporaryDirectory() as output_dir_name:
                subprocess.check_call(
                    ["svn", "co", remote_url, "--depth", "empty", output_dir_name],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            logger.info("Successfully cloned %s, that means it's a public repo - not reporting", remote_url)
            return []
        except Exception as e:
            logger.info("Failed to clone, that means it may be a private repo - reporting (error=%s)", repr(e))
            return [
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=db_url,
                    report_type=VCSReporter.EXPOSED_VERSION_CONTROL_FOLDER,
                    timestamp=task_result["created_at"],
                )
            ]
        return []

    @staticmethod
    def _create_reports_git(task_result: Dict[str, Any], language: Language) -> List[Report]:
        repo_url = urllib.parse.urljoin(get_target_url(task_result), ".git/")
        config_url = urllib.parse.urljoin(repo_url, "config")

        logger.info("Analysing Git folder in %s", repo_url)
        with tempfile.NamedTemporaryFile() as f:
            try:
                data = cached_get(config_url).content_bytes
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                return []

            if "[core]" not in data.decode("utf-8", errors="ignore"):
                return []

            try:
                remote_url = (
                    subprocess.check_output(
                        [
                            "git",
                            "config",
                            "-f",
                            f.name,
                            "--get",
                            "remote.origin.url",
                        ]
                    )
                    .decode("ascii")
                    .strip()
                )
            except Exception:
                remote_url = None

        if remote_url and (remote_url.startswith("http://") or remote_url.startswith("https://")):
            parsed_remote_url = urllib.parse.urlparse(remote_url)
            if parsed_remote_url.password:
                return [
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=config_url,
                        report_type=VCSReporter.EXPOSED_VERSION_CONTROL_FOLDER_WITH_CREDENTIALS,
                        additional_data={
                            "username": parsed_remote_url.username,
                            "password_prefix": parsed_remote_url.password[:3],
                        },
                        timestamp=task_result["created_at"],
                    )
                ]

        report = Report(
            top_level_target=get_top_level_target(task_result),
            target=config_url,
            report_type=VCSReporter.EXPOSED_VERSION_CONTROL_FOLDER,
            timestamp=task_result["created_at"],
        )

        if not remote_url:  # local repo - something we want to report
            logger.info("No remote url, reporting")
            return [report]

        logger.info("Successfully obtained remote url: %s", remote_url)

        try:
            with tempfile.TemporaryDirectory() as output_dir_name:
                subprocess.check_call(
                    [
                        "git",
                        "clone",
                        "--depth",
                        "1",
                        remote_url,
                        "--filter=blob:none",
                        "--no-checkout",
                        output_dir_name,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={
                        "GIT_SSH_COMMAND": "ssh -o PasswordAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no",
                        "GIT_TERMINAL_PROMPT": "0",
                    },
                    timeout=30,
                )
            logger.info("Successfully cloned %s, that means it's a public repo - not reporting", remote_url)
            return []
        except Exception as e:
            logger.info("Failed to clone, that means it may be a private repo - reporting (error=%s)", repr(e))
            return [report]

        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_exposed_version_control_folder.jinja2"), priority=7
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(
                    os.path.dirname(__file__), "template_exposed_version_control_folder_with_credentials.jinja2"
                ),
                priority=8,
            ),
        ]
