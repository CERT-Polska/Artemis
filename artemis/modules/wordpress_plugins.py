#!/usr/bin/env python3
import binascii
import json
import os
import re
import string
import urllib
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.domains import is_subdomain
from artemis.fallback_api_cache import FallbackAPICache
from artemis.module_base import ArtemisBase

# Some readmes are long, longer than the default 100kb
README_MAX_SIZE = 1024 * 1024

FILE_NAME_CANDIDATES = ["readme.txt", "README.txt", "README.TXT", "readme.md", "README.md", "Readme.txt"]
PLUGINS_WITH_REVERSED_CHANGELOGS = [
    "appointment-hour-booking",
    "bulk-page-creator",
    "button-contact-vr",
    "country-phone-field-contact-form-7",
    "customizer-export-import",
    "delete-all-comments-of-website",
    "disable-xml-rpc-api",
    "flowpaper-lite-pdf-flipbook",
    "metricool",
    "sumome",
    "userway-accessibility-widget",
    "visual-footer-credit-remover",
    "wp-events-manager",
    "zarinpal-woocommerce-payment-gateway",
]
PLUGINS_TO_SKIP_CHANGELOG = [
    "backwpup",
    "everest-forms",
    "social-pug",
    "wordpress-popup",
    "wp-members",
    "wppao-sitemap",
    "yith-woocommerce-catalog-mode",
]
PLUGINS_TO_SKIP_STABLE_TAG = [
    "flowpaper-lite-pdf-flipbook",
    "scheduled-post-trigger",
    "pdf-viewer-for-elementor",
    "wow-carousel-for-divi-lite",
]
PLUGINS_BAD_VERSION_IN_README = [
    "cf7-styler-for-divi",
    "coming-soon",
    "delete-all-comments-of-website",
    "disable-remove-google-fonts",
    "famethemes-demo-importer",
    "icon-element",
    "link-manager",
    "login-logo",
    "page-or-post-clone",
    "rafflepress",
    "skyboot-custom-icons-for-elementor",
    "two-factor",
    "website-monetization-by-magenet",
    "woo-tools",
    "wp-maximum-execution-time-exceeded",
]


def strip_trailing_zeros(version: Optional[str]) -> Optional[str]:
    if not version:
        return None

    version_split = version.split(".")
    while len(version_split) > 0 and set(version_split[-1]) == set("0"):
        version_split.pop()
    return ".".join(version_split)


def _is_version_larger(v1: str, v2: str) -> bool:
    v1_stripped = strip_trailing_zeros(v1)
    v2_stripped = strip_trailing_zeros(v2)

    if not v1_stripped or not v2_stripped:
        return False

    v1_split = v1_stripped.split(".")
    v2_split = v2_stripped.split(".")

    while len(v1_split) > len(v2_split):
        v2_split.append("0")
    while len(v1_split) < len(v2_split):
        v1_split.append("0")

    for item1, item2 in zip(v1_split, v2_split):
        try:
            if int(item1) > int(item2):
                return True
            if int(item1) < int(item2):
                return False
        except ValueError:
            if item1 > item2:
                return True
            if item1 < item2:
                return False
    return False


def get_version_from_readme(slug: str, readme_content: str) -> Optional[str]:
    previous_line = ""
    changelog_version = None

    # Some plugins' changelogs are reversed
    if slug in PLUGINS_WITH_REVERSED_CHANGELOGS:
        has_reversed_changelog = True
    else:
        has_reversed_changelog = False

    if slug == "userway-accessibility-widget":
        # No changelog header in this plugin's readme
        readme_content = readme_content.replace("= 1.1 =", "Changelog")

    if slug == "image-sizes":
        # Changelog entries prefixed with dates
        readme_content = re.sub(r"^= \d{4}-\d{2}-\d{2}", "", readme_content, flags=re.MULTILINE)

    if slug not in PLUGINS_TO_SKIP_CHANGELOG:
        seen_changelog_line = False
        for line in readme_content.lower().split("\n"):
            line = line.strip("= #[]\r\t")
            if not line:
                continue

            # Happens between changelog header and version, let's skip
            if (
                line.startswith("for the plugin's full changelog")
                or line.startswith("this changelog is for")
                or line.startswith("for detailed release notes")
                or line.startswith("-----")
            ):
                continue

            if previous_line == "changelog" or (has_reversed_changelog and seen_changelog_line):
                seen_changelog_line = True
                # Some changelog entries have the format <slug>: <version>
                if line.startswith(slug):
                    line = line[len(slug) :].strip(" :")
                # Some changelog entries have the format version <version>
                # let's take only first 25 characters as the "version" word may occur in a middle of a sentence
                if "version" in line[:25]:
                    line = line[line.find("version") + len("version") :].strip(" :")
                # Some changelog entries have the format V <version> - let's match them but with word-boundary matcher
                # so that we don't match "nov"
                if re.search(r"\bv ", line):
                    line = line[line.find("v ") + len("v ") :].strip(" :")
                if line.startswith("v"):
                    line = line[1:]

                version = (
                    re.sub(r"(\(|\*|\[|\]|/|'|:|,|-|=|<h4>|</h4>)", " ", line)
                    .strip()
                    # Some versions are prefixed with 'v' (e.g. v1.0.0)
                    .lstrip("v")
                    .split(" ")[0]
                )
                if (
                    "." in version
                    and version[0] in string.digits
                    and (not changelog_version or _is_version_larger(version, changelog_version))
                ):
                    changelog_version = version
                    if not has_reversed_changelog:
                        break

            previous_line = line

    # Some plugins have broken "stable tag"
    if slug in PLUGINS_TO_SKIP_STABLE_TAG:
        return changelog_version

    tag_lines = [line for line in readme_content.lower().split("\n") if line.strip("* -\t").startswith("stable tag")]
    if len(tag_lines) > 1:
        return changelog_version

    if tag_lines:
        (tag_line,) = tag_lines
        tag = tag_line.strip(" -\t").split(":")[1].strip().lstrip("v")

        if tag != "trunk" and (
            # Sometimes the changelog version is greater, sometimes the "stable tag" version is greater -
            # let's pick the greater one as the version.
            changelog_version is None
            or _is_version_larger(tag, changelog_version)
        ):
            return tag
    return changelog_version


def _get_host_from_url(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    assert host is not None
    return host


class WordpressPluginsScanningException(Exception):
    pass


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class WordpressPlugins(ArtemisBase):
    """
    Checks whether WordPress plugins are up-to-date.
    """

    identity = "wordpress_plugins"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.WORDPRESS.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        response = FallbackAPICache.Urls.WORDPRESS_PLUGINS_LIST.value.get()
        json_response = response.json()
        self._top_plugins = [
            {
                "repository_version": plugin["version"],
                "slug": plugin["slug"],
            }
            for plugin in json_response["plugins"]
            if plugin["slug"] not in PLUGINS_BAD_VERSION_IN_README
        ]
        self._top_plugin_slugs = [plugin["slug"] for plugin in self._top_plugins]
        with open(os.path.join(os.path.dirname(__file__), "data", "wordpress_plugin_readme_file_names.txt")) as f:
            self._readme_file_names = json.load(f)

    def _get_plugins_from_homepage(self, url: str) -> List[Dict[str, Any]]:
        links = get_links_and_resources_on_same_domain(url)

        plugin_data = []
        for link in links:
            pattern = r"\/wp-content\/plugins\/([a-z-0-9]*)\/"
            match = re.search(pattern, link)
            if match:
                slug = match.group(1)
                data = FallbackAPICache.get(
                    f"https://api.wordpress.org/plugins/info/1.0/{slug}.json", allow_unknown=True
                ).json()

                plugin_data.append(
                    {
                        "slug": slug,
                        "repository_version": data.get("version", None),
                    }
                )

        return plugin_data

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        response = self.http_get(url)
        not_scanning_redirect_message = None
        if response.is_redirect:
            redirect_url = response.url
            self.log.warning("detected a redirect to %s", redirect_url)

            # The redirect handling is done here, not as a general "module feature", because the handling logic differs
            # between modules. For example, we may have a site that redirects to other URL, but we still want to check
            # for /server-status/ or .git, as the redirect may not be complete.
            #
            # Here, if the website redirects, the heuristic is as follows:
            # - if we cannot determine the redirect URL, we naturally cannot redirect,
            # - if we cannot determine whether the redirect is in scope, because original_domain is not provided, or
            #   the redirect domain is out of scope (not a subdomain of original_domain), we decide we're not allowed
            #   to scan,
            # - if the site redirects to a parent domain (e.g. subdomain.example.com -> example.com) we don't scan as
            #   it may be the case that old domains are redirected by a wildcard redirect and we would duplicate vulns,
            # - all other redirects (e.g. domain1.example.com -> domain2.example.com, example.com ->
            #   subdomain.example.com, ...) are considered interesting and will be scanned.
            redirect_host = _get_host_from_url(redirect_url)
            url_host = _get_host_from_url(url)
            if "original_domain" not in current_task.payload_persistent:
                not_scanning_redirect_message = (
                    "The scan was initiated from an IP - not knowing whether the redirect target should be scanned"
                )
            elif not redirect_url:
                not_scanning_redirect_message = "Unable to obtain the redirect url"
            elif not is_subdomain(redirect_host, current_task.payload_persistent["original_domain"]):
                not_scanning_redirect_message = (
                    "The redirect target is not a subdomain of "
                    f'{current_task.payload_persistent["original_domain"]}, not scanning'
                )
            elif is_subdomain(url_host, redirect_host) and url_host != redirect_host:
                not_scanning_redirect_message = (
                    "The redirect target is a parent url of a current URL, not scanning as we will return duplicates"
                )
            else:
                self.log.warning("%s redirects to %s, re-running scan", url, redirect_url)
                url = response.url
        else:
            redirect_url = None

        if not_scanning_redirect_message:
            self.log.warning(
                not_scanning_redirect_message,
            )
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=not_scanning_redirect_message,
            )
            return

        plugins: Dict[str, Dict[str, Any]] = {}
        outdated_plugins = []
        seen_plugins = set()
        for plugin in self._get_plugins_from_homepage(url) + self._top_plugins:
            if plugin["slug"] in seen_plugins:
                continue

            seen_plugins.add(plugin["slug"])

            # Sometimes the README content is cached on the server side, let's bust the cache
            cachebuster = "?" + binascii.hexlify(os.urandom(10)).decode("ascii")

            try:
                if plugin["slug"] in self._readme_file_names:
                    response = self.http_get(
                        urllib.parse.urljoin(
                            url,
                            "/wp-content/plugins/"
                            + plugin["slug"]
                            + "/"
                            + self._readme_file_names[plugin["slug"]]
                            + cachebuster,
                        ),
                        max_size=README_MAX_SIZE,
                    )
                else:
                    for file_name in FILE_NAME_CANDIDATES:
                        response = self.http_get(
                            urllib.parse.urljoin(
                                url, "/wp-content/plugins/" + plugin["slug"] + "/" + file_name + cachebuster
                            ),
                            max_size=README_MAX_SIZE,
                        )
                        if "stable tag" in response.content.lower():
                            break
                if "stable tag" not in response.content.lower():
                    continue
            except requests.exceptions.RequestException:
                self.log.exception("Unable to obtain plugin version for %s", plugin["slug"])
                continue

            version = get_version_from_readme(plugin["slug"], response.content)
            if version:
                plugins[plugin["slug"]] = {
                    "version": version,
                }

                if _is_version_larger(plugin["repository_version"], version):
                    if (
                        not Config.Modules.WordPressPlugins.WORDPRESS_SKIP_VERSION_CHECK_ON_LESS_POPULAR_PLUGINS
                        or plugin["slug"] in self._top_plugin_slugs
                    ):
                        outdated_plugins.append(
                            {
                                "slug": plugin["slug"],
                                "version": version,
                            }
                        )

        messages = []
        closed_plugins = []
        for plugin_slug in plugins.keys():
            existed = (
                len(
                    FallbackAPICache.get(
                        f"https://api.wordpress.org/stats/plugin/1.0/{plugin_slug}", allow_unknown=True
                    ).json()
                )
                > 0
            )
            plugin_data = FallbackAPICache.get(
                f"https://api.wordpress.org/plugins/info/1.0/{plugin_slug}.json", allow_unknown=True
            ).json()
            still_exists = "error" not in plugin_data

            if existed and not still_exists:
                messages.append(f"Found closed plugin: {plugin_slug}")
                closed_plugins.append(plugin_slug)

        outdated = []
        for plugin in outdated_plugins:
            messages.append(f"Outdated plugin found: {plugin['slug']} {plugin['version']}")
            outdated.append(
                {
                    "type": "plugin",
                    "slug": plugin["slug"],
                    "version": plugin["version"],
                }
            )

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "outdated": outdated,
                "plugins": plugins,
                "closed_plugins": closed_plugins,
                "redirect_url": redirect_url,
            },
        )


if __name__ == "__main__":
    WordpressPlugins().loop()
