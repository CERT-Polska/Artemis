#!/usr/bin/env python3
import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Tuple

from karton.core import Task
from packaging import version

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.module_base import ArtemisBase

EXTENSIONS_FILE = os.path.join(os.path.dirname(__file__), "data", "joomla", "extensions.json")

CORE_COMPONENTS = {
    "com_admin",
    "com_ajax",
    "com_associations",
    "com_banners",
    "com_cache",
    "com_categories",
    "com_checkin",
    "com_config",
    "com_contact",
    "com_content",
    "com_contenthistory",
    "com_cpanel",
    "com_csp",
    "com_fields",
    "com_finder",
    "com_installer",
    "com_joomlaupdate",
    "com_languages",
    "com_login",
    "com_mailto",
    "com_media",
    "com_menus",
    "com_messages",
    "com_modules",
    "com_newsfeeds",
    "com_plugins",
    "com_postinstall",
    "com_redirect",
    "com_search",
    "com_tags",
    "com_templates",
    "com_users",
    "com_workflow",
    "com_wrapper",
}

CORE_MODULES = {"mod_languages", "mod_menu"}

CORE_PLUGIN_GROUPS = (
    "content",
    "system",
    "user",
    "authentication",
    "search",
    "editors",
    "editors-xtd",
    "finder",
    "extension",
    "fields",
    "privacy",
    "quickicon",
    "actionlog",
    "console",
    "installer",
    "task",
    "webservices",
    "captcha",
    "ajax",
    "filesystem",
    "sampledata",
    "media-action",
    "behaviour",
)

JED_SLUG_RE = re.compile(r"/extension/([^/]+)/?$")


def normalize_key(s: str | None) -> str:
    if not s:
        return ""
    s = s.lower().strip()
    for prefix in ("plg_", "com_", "mod_"):
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    return re.sub(r"[^a-z0-9]", "", s)


def extract_jed_slug(jed_url: str) -> str:
    if not jed_url:
        return ""
    m = JED_SLUG_RE.search(jed_url)
    return m.group(1) if m else ""


def parse_version_string(raw: str | None) -> version.Version | None:
    if not raw:
        return None
    raw = raw.strip()
    if " " in raw:
        for part in raw.split():
            try:
                return version.parse(part)
            except version.InvalidVersion:
                continue
        return None
    try:
        return version.parse(raw)
    except version.InvalidVersion:
        return None


def parse_manifest_xml(xml_text: str) -> dict[str, str | None] | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    if not root.tag.endswith("extension") and root.tag != "extension":
        for child in root.iter():
            if child.tag.endswith("extension") or child.tag == "extension":
                root = child
                break

    def localname(tag: str) -> str:
        return tag.split("}")[-1] if "}" in tag else tag

    name: str | None = None
    ext_version: str | None = None
    for elem in root:
        ln = localname(elem.tag)
        if ln == "name" and name is None:
            name = (elem.text or "").strip()
        elif ln == "version" and ext_version is None:
            ext_version = (elem.text or "").strip()

    if not name and not ext_version:
        return None
    return {"name": name, "version": ext_version}


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class JoomlaExtensions(ArtemisBase):
    """
    Checks whether Joomla! extensions are up-to-date by fetching their manifest XML
    files and comparing the detected version against the JED-derived extensions index.
    """

    identity = "joomla_extensions"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.JOOMLA.value},
    ]
    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._by_name: dict[str, dict[str, Any]] = {}
        self._by_normalized: dict[str, dict[str, Any]] = {}
        with open(EXTENSIONS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        entries = data.get("extensions", data) if isinstance(data, dict) else data
        for ext in entries:
            name = ext.get("extension_name")
            if name:
                self._by_name[name.lower()] = ext
            slug = extract_jed_slug(ext.get("jed_url", ""))
            for nk in (normalize_key(slug), normalize_key(name)):
                if nk:
                    self._by_normalized.setdefault(nk, ext)

    def fetch_manifest(self, url: str) -> dict[str, str | None] | None:
        response = self.forgiving_http_get(url)
        if response is None or response.status_code != 200:
            return None
        content_type = response.headers.get("Content-Type", "").lower()
        if "xml" not in content_type:
            return None
        result = parse_manifest_xml(response.content)
        if result:
            result["manifest_url"] = url
        return result

    def check_for_component(self, base_url: str, com_name: str) -> dict[str, str | None] | None:
        paths = [
            "/administrator/components/" + com_name + "/manifest.xml",
            "/administrator/components/" + com_name + "/" + com_name[4:] + ".xml",
            "/administrator/components/" + com_name + "/" + com_name + ".xml",
        ]
        for path in paths:
            result = self.fetch_manifest(base_url + path)
            if result:
                return result
        return None

    def check_for_module(self, base_url: str, mod_name: str) -> dict[str, str | None] | None:
        paths = [
            "/modules/" + mod_name + "/" + mod_name + ".xml",
            "/administrator/modules/" + mod_name + "/" + mod_name + ".xml",
        ]
        for path in paths:
            result = self.fetch_manifest(base_url + path)
            if result:
                return result
        return None

    def check_for_plugin(self, base_url: str, plg_name: str) -> dict[str, str | None] | None:
        for group in CORE_PLUGIN_GROUPS:
            path = "/plugins/" + group + "/" + plg_name + "/" + plg_name + ".xml"
            result = self.fetch_manifest(base_url + path)
            if result:
                return result
        return None

    def _result_body(self, type: str, key: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": type,
            "key": key,
            "name": result["name"],
            "version": result["version"],
            "manifest_url": result["manifest_url"],
        }

    def detect_extensions(self, base_url: str, html: str) -> list[dict[str, Any]]:
        detected: list[dict[str, Any]] = []

        index_components = set(re.findall(r"com_\w+", html)) - CORE_COMPONENTS
        index_modules = set(re.findall(r"mod_\w+", html)) - CORE_MODULES
        index_plugins = set(re.findall(r"plg_\w+", html))

        self.log.info(
            "blob identification: %d components, %d modules, %d plugins",
            len(index_components),
            len(index_modules),
            len(index_plugins),
        )

        for key in sorted(index_components):
            result = self.check_for_component(base_url, key)
            if result:
                detected.append(self._result_body("component", key, result))

        for key in sorted(index_modules):
            result = self.check_for_module(base_url, key)
            if result:
                detected.append(self._result_body("module", key, result))

        for key in sorted(index_plugins):
            plg_name = key[4:] if key.startswith("plg_") else key
            result = self.check_for_plugin(base_url, plg_name)
            if result:
                detected.append(self._result_body("plugin", key, result))

        return detected

    def _compare_extensions(self, detected: list[dict[str, Any]]) -> Tuple[list[dict[str, Any]], list[str]]:
        extensions: list[dict[str, Any]] = []
        outdated: list[str] = []

        for ext in detected:
            site_version = parse_version_string(ext.get("version"))
            entry: dict[str, Any] = {
                "type": ext["type"],
                "key": ext["key"],
                "name": ext["name"],
                "version": ext["version"],
                "manifest_url": ext["manifest_url"],
                "latest_version": None,
                "outdated": None,
            }

            match: dict[str, Any] | None = None
            site_key_norm = normalize_key(ext["key"])
            if site_key_norm:
                match = self._by_normalized.get(site_key_norm)
            if match is None and ext["name"]:
                match = self._by_normalized.get(normalize_key(ext["name"]))
            if match is None and ext["name"]:
                match = self._by_name.get(ext["name"].lower())

            if match:
                latest = match.get("latest_version")
                entry["latest_version"] = latest
                if latest and site_version:
                    try:
                        entry["outdated"] = site_version < version.parse(latest)
                    except version.InvalidVersion:
                        entry["outdated"] = None

            extensions.append(entry)
            if entry["outdated"] is True:
                outdated.append(ext["name"])
                self.log.info(
                    "OUTDATED: %s site=%s latest=%s",
                    ext["name"],
                    ext["version"],
                    entry["latest_version"],
                )

        return extensions, outdated

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        response = self.http_get(url)
        if response.status_code != 200:
            self.log.info("index returned HTTP %d, aborting detection", response.status_code)
            self.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=f"Index returned HTTP {response.status_code}",
                data={"extensions": [], "outdated": []},
            )
            return

        base_url = response.url.rstrip("/")
        detected = self.detect_extensions(base_url, response.content)
        extensions, outdated = self._compare_extensions(detected)

        if outdated:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(f"Outdated Joomla! extension: {name}" for name in outdated)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "extensions": extensions,
                "outdated": outdated,
            },
        )


if __name__ == "__main__":
    JoomlaExtensions.parallel_loop()
