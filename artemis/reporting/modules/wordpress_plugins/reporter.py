import os
import re
from typing import Any, Callable, Dict, List, Set

from packaging import version

from artemis import utils
from artemis.fallback_api_cache import FallbackAPICache
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_target_url, get_top_level_target

logger = utils.build_logger(__name__)


class WordpressPluginsReporter(Reporter):
    WORDPRESS_OUTDATED_PLUGIN_THEME = ReportType("wordpress_outdated_plugin_theme")
    CLOSED_WORDPRESS_PLUGIN = ReportType("closed_wordpress_plugin")

    VERSION_RE = re.compile("Version.{0,10}<strong>([^<]*)</strong>")

    CLOSED_PLUGINS: Set[str] = set()

    @staticmethod
    def is_version_known_to_wordpress(plugin_slug: str, plugin_version: str) -> bool:
        # Some plugins don't have the latest version as a tag on SVN repo
        plugin_site_response = FallbackAPICache.get(f"https://wordpress.org/plugins/{plugin_slug}/", allow_unknown=True)
        if plugin_site_response.status_code == 404:
            return False  # developed outside repo

        re_match = re.search(WordpressPluginsReporter.VERSION_RE, plugin_site_response.text)
        if not re_match:  # the site is overloaded or other problem - let's fall back to considering the version known
            logger.error(f"Unable to extract version information about {plugin_slug}")
            return True

        (latest_version,) = re_match.groups(1)

        if latest_version == plugin_version:
            return True

        try:
            assert isinstance(latest_version, str)
            if version.parse(latest_version) >= version.parse(plugin_version):
                return True
        except version.InvalidVersion:
            pass

        return False

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "wordpress_plugins":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for slug in task_result["result"].get("closed_plugins", []):
            plugin_data = task_result["result"]["plugins"][slug]
            if plugin_data["version"]:
                version = plugin_data["version"]
                version_exists = WordpressPluginsReporter.is_version_known_to_wordpress(slug, version)
            else:
                # If no version number, let's assume it's one known to WordPress, so the
                # plugin is *not* developed separately.
                version_exists = True

            if version_exists:
                WordpressPluginsReporter.CLOSED_PLUGINS.add(slug)
                result.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=get_target_url(task_result),
                        report_type=WordpressPluginsReporter.CLOSED_WORDPRESS_PLUGIN,
                        additional_data={"slug": slug},
                        timestamp=task_result["created_at"],
                    )
                )
            else:
                logger.info(f"{slug} version {version} developed outside WordPress repo")

        for item in task_result["result"]["outdated"]:
            additional_data = {
                "type": item["type"],
                "slug": item["slug"],
                "version": item["version"],
            }

            if "redirect_url" in task_result["result"]:
                additional_data["redirect_url"] = task_result["result"]["redirect_url"]

            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=get_target_url(task_result),
                    report_type=WordpressPluginsReporter.WORDPRESS_OUTDATED_PLUGIN_THEME,
                    additional_data=additional_data,
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_closed_wordpress_plugin.jinja2"), 6
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_wordpress_outdated_plugin_theme.jinja2"), 4
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {
            WordpressPluginsReporter.CLOSED_WORDPRESS_PLUGIN: Reporter.default_scoring_rule,
            WordpressPluginsReporter.WORDPRESS_OUTDATED_PLUGIN_THEME: Reporter.default_scoring_rule,
        }

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            WordpressPluginsReporter.CLOSED_WORDPRESS_PLUGIN: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "slug": report.additional_data["slug"],
                }
            ),
            WordpressPluginsReporter.WORDPRESS_OUTDATED_PLUGIN_THEME: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "object_type": report.additional_data["type"],
                    "object_slug": report.additional_data["slug"],
                    "object_version": report.additional_data["version"],
                }
            ),
        }
