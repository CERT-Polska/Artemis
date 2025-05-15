import io
import json
import unittest
import zipfile
from typing import Any, Dict, List

import chardet
import requests

from artemis.modules.wordpress_plugins import (
    FILE_NAME_CANDIDATES,
    PLUGINS_BAD_VERSION_IN_README,
    get_version_from_readme,
    strip_trailing_zeros,
)
from artemis.utils import build_logger

with open("/opt/artemis/modules/data/wordpress_plugin_readme_file_names.txt", "r") as f:
    README_FILE_NAMES = json.load(f)

LOGGER = build_logger(__name__)

# As of 2025-05-15, the plugin doesn't have a readme to obtain version from
PLUGINS_TO_SKIP_TESTING = ["leadconnector"]


class WordpressPluginIdentificationTestCase(unittest.TestCase):
    num_plugins = 1500

    def test_plugin_identification_from_readme(self) -> None:
        plugins: List[Dict[str, Any]] = []
        page = 1
        while len(plugins) < self.num_plugins:
            response = requests.get(
                "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=%d&request[per_page]=100"
                % page
            )
            json_response = response.json()
            plugins.extend(
                [
                    {
                        "version": plugin["version"],
                        "slug": plugin["slug"],
                    }
                    for plugin in json_response["plugins"]
                ]
            )
            page += 1
        plugins = plugins[: self.num_plugins]

        plugins = [plugin for plugin in plugins if not plugin["slug"] in PLUGINS_TO_SKIP_TESTING]

        good = set()
        bad = set()
        bad_explained = set()
        for i, plugin in enumerate(plugins):
            response = requests.get(f"https://downloads.wordpress.org/plugin/{plugin['slug']}.{plugin['version']}.zip")
            if response.status_code != 200:
                response = requests.get(f"https://downloads.wordpress.org/plugin/{plugin['slug']}.zip")

            try:
                with zipfile.ZipFile(io.BytesIO(response.content), "r") as f:
                    readme_file_name = README_FILE_NAMES.get(plugin["slug"], None)
                    if not readme_file_name:
                        for readme_file_name_candidate in FILE_NAME_CANDIDATES:
                            try:
                                f.read(f"{plugin['slug']}/{readme_file_name_candidate}")
                                readme_file_name = readme_file_name_candidate
                                break
                            except KeyError:
                                pass
                        README_FILE_NAMES[plugin["slug"]] = readme_file_name

                    readme_contents = self._decode(f.read(f"{plugin['slug']}/{readme_file_name}"))
            except zipfile.BadZipFile:
                LOGGER.error(f"Bad zip file for slug {plugin['slug']}: {repr(response.content[:100])}")
                continue

            version_from_readme = get_version_from_readme(plugin["slug"], readme_contents)

            if strip_trailing_zeros(version_from_readme) == strip_trailing_zeros(plugin["version"]):
                good.add(plugin["slug"])
            else:
                bad.add(plugin["slug"])
                bad_explained.add(f"{plugin['slug']}: {version_from_readme} != {plugin['version']}")

            if i % 100 == 0:
                LOGGER.info("Versions identified correctly=%d, incorrectly=%d (%s)", len(good), len(bad), bad_explained)

            with open("/opt/artemis/modules/data/wordpress_plugin_readme_file_names.txt", "w") as f:
                json.dump(README_FILE_NAMES, f)

        LOGGER.info("Versions identified correctly=%d, incorrectly=%d (%s)", len(good), len(bad), bad_explained)
        self.assertEqual(set(bad), set(PLUGINS_BAD_VERSION_IN_README))

    def _decode(self, data: bytes) -> str:
        encoding = chardet.detect(data)["encoding"]
        return data.decode(encoding or "utf-8", errors="ignore")
