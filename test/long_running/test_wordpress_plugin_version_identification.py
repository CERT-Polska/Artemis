from typing import Optional

import chardet
import io
import json
import subprocess
import requests
import unittest
import zipfile

from artemis.modules.wordpress_plugins import FILE_NAME_CANDIDATES, get_version_from_readme

with open("/opt/artemis/modules/data/wordpress_plugin_readme_file_names.txt", "r") as f:
    README_FILE_NAMES = json.load(f)


class WordpressPluginIdentificationTestCase(unittest.TestCase):
    num_plugins = 2000

    def test_plugin_identification_from_readme(self):
        plugins = []
        page = 1
        while len(plugins) < self.num_plugins:
            response = requests.get(
                "https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[page]=%d&request[per_page]=100"
                % page
            )
            json_response = response.json()
            plugins.extend([
            {
                "version": plugin["version"],
                "slug": plugin["slug"],
            } for plugin in json_response["plugins"]])
        plugins = plugins[:self.num_plugins]

        good = set()
        bad = set()
        for plugin in plugins:
            response = requests.get(f"https://downloads.wordpress.org/plugin/{plugin['slug']}.{plugin['version']}.zip")
            try:
                with zipfile.ZipFile(io.BytesIO(response.content), 'r') as f:
                    readme_file_name = README_FILE_NAMES.get(plugin['slug'], None)
                    if not readme_file_name:
                        for readme_file_name_candidate in FILE_NAME_CANDIDATES:
                            try:
                                f.read(f"{plugin['slug']}/{readme_file_name_candidate}")
                                readme_file_name = readme_file_name_candidate
                                break
                            except KeyError:
                                pass
                        README_FILE_NAMES[plugin['slug']] = readme_file_name

                    readme_contents = self._decode(f.read(f"{plugin['slug']}/{readme_file_name}"))
            except zipfile.BadZipFile:
                continue
            version_from_readme = get_version_from_readme(plugin['slug'], readme_contents)

            if version_from_readme == plugin["version"]:
                good.add(plugin['slug'])
            else:
                bad.add(f"{plugin['slug']}: {version_from_readme} != {plugin['version']}")

            print(len(good), len(bad), bad)
            with open("/opt/artemis/modules/data/wordpress_plugin_readme_file_names.txt", "w") as f:
                json.dump(README_FILE_NAMES, f)

        self.assertTrue(bad < 0.005 * self.num_plugins)

    def _decode(self, data: bytes) -> str:
        encoding = chardet.detect(data)['encoding']
        return data.decode(encoding or 'utf-8', errors='ignore')
