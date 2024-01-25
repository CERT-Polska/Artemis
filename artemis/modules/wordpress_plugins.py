#!/usr/bin/env python3
import json
import os
import re
import urllib
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup
from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase

FILE_NAME_CANDIDATES = ["readme.txt", "README.txt", "README.TXT", "readme.md", "README.md", "Readme.txt"]
PLUGINS_WITH_REVERSED_CHANGELOGS = [
    "bulk-page-creator",
    "button-contact-vr",
    "country-phone-field-contact-form-7",
    "customizer-export-import",
    "delete-all-comments-of-website",
    "disable-xml-rpc-api",
    "metricool",
    "sumome",
    "visual-footer-credit-remover",
    "zarinpal-woocommerce-payment-gateway",
]
PLUGINS_TO_SKIP_CHANGELOG = ["wp-members"]
PLUGINS_TO_SKIP_STABLE_TAG = ["scheduled-post-trigger", "pdf-viewer-for-elementor"]


def get_version_from_readme(slug: str, readme_content: str) -> Optional[str]:
    previous_line = ""
    changelog_version = None

    # These plugins' changelogs are reversed
    if slug in PLUGINS_WITH_REVERSED_CHANGELOGS:
        has_reversed_changelog = True
    else:
        has_reversed_changelog = False

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
                or line.startswith("-----")
            ):
                continue

            if previous_line == "changelog" or (has_reversed_changelog and seen_changelog_line):
                seen_changelog_line = True
                # Some changelog entries have the format <slug>: <version>
                if line.startswith(slug):
                    line = line[len(slug) :].strip(" :")
                # Some changelog entries have the format version <version>
                if "version" in line:
                    line = line[line.find("version") + len("version") :].strip(" :")
                # Some changelog entries have the format V <version>
                if "v " in line:
                    line = line[line.find("v ") + len("v ") :].strip(" :")
                version = (
                    re.sub(r"(\(|\*|\[|\]|/|'|:|,|-|<h4>|</h4>)", " ", line)
                    .strip()
                    # Some versions are prefixed with 'v' (e.g. v1.0.0)
                    .lstrip("v")
                    .split(" ")[0]
                )
                if "." in version:
                    changelog_version = version
                    if not has_reversed_changelog:
                        break

            previous_line = line

    # Some plugins have broken "stable tag"
    if slug in PLUGINS_TO_SKIP_STABLE_TAG:
        return changelog_version

    tag_lines = [line for line in readme_content.lower().split("\n") if line.strip("* ").startswith("stable tag")]
    if len(tag_lines) > 1:
        return changelog_version

    if tag_lines:
        (tag_line,) = tag_lines
        tag = tag_line.strip().split(":")[1].strip()

        if tag != "trunk" and (
            # Sometimes the changelog version is greater, sometimes the "stable tag" version is greater -
            # let's pick the greater one as the version.
            changelog_version is None
            or tuple(tag.split(".")) > tuple(changelog_version.split("."))
        ):
            return tag
    return changelog_version


def _get_host_from_url(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    assert host is not None
    return host


def _get_plugins_from_homepage(url: str) -> List[Dict[str, Any]]:
    url_parsed = urllib.parse.urlparse(url)
    response = http_requests.get(url)
    soup = BeautifulSoup(response.text)
    links = []
    for tag in soup.find_all():
        new_url = None
        for attribute in ["src", "href"]:
            if attribute not in tag.attrs:
                continue

            new_url = urllib.parse.urljoin(url, tag[attribute])
            new_url_parsed = urllib.parse.urlparse(new_url)

            if url_parsed.netloc == new_url_parsed.netloc:
                links.append(new_url)

    plugin_data = []
    for link in links:
        pattern = r"\/wp-content\/plugins\/([a-z-0-9]*)\/"
        match = re.search(pattern, link)
        if match:
            plugin_data.append({"slug": match.group(1)})

    return plugin_data


class WordpressPluginsScanningException(Exception):
    pass


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
        response = requests.get(
            "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=1&request[per_page]=1000"
        )
        json_response = response.json()
        self._top_plugins = [
            {
                "version": plugin["version"],
                "slug": plugin["slug"],
            }
            for plugin in json_response["plugins"]
        ]
        with open(os.path.join(os.path.dirname(__file__), "data", "wordpress_plugin_readme_file_names.txt")) as f:
            self._readme_file_names = json.load(f)

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        response = http_requests.get(url)
        if response.is_redirect:
            redirect_url = response.url
            self.log.warning("detected a redirect to %s", redirect_url)

            not_scanning_redirect_message = None
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
        for plugin in self._top_plugins + _get_plugins_from_homepage(url):
            if plugin["slug"] in self._readme_file_names:
                response = http_requests.get(
                    url + "/wp-content/plugins/" + plugin["slug"] + "/" + self._readme_file_names[plugins["slug"]]
                )
            else:
                for file_name in FILE_NAME_CANDIDATES:
                    response = http_requests.get(url + "/wp-content/plugins/" + plugin["slug"] + "/" + file_name)
                    if "stable tag:" in response.content.lower():
                        break
            if "stable tag:" not in response.content.lower():
                continue

            version = get_version_from_readme(plugin["slug"], response.content)
            if version:
                plugins[plugin["slug"]] = {
                    "version": version,
                }

                if version != plugin["version"]:
                    outdated_plugins.append(
                        {
                            "slug": plugin["slug"],
                            "version": version,
                        }
                    )

        messages = []
        closed_plugins = []
        for plugin_slug in plugins.keys():
            existed = len(requests.get("https://api.wordpress.org/stats/plugin/1.0/" + plugin_slug).json()) > 0
            plugin_data = requests.get(f"https://api.wordpress.org/plugins/info/1.0/{plugin_slug}.json").json()
            still_exists = "error" not in plugin_data

            if existed and not still_exists:
                messages.append(f"Found closed plugin: {plugin_slug}")
                closed_plugins.append(plugin_slug)

        outdated = []
        for plugin in outdated_plugins:
            messages.append(f"Outdated plugin found: {plugin['slug']} {plugin['version']}")
            outdated.append(
                {
                    "type": plugin,
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
