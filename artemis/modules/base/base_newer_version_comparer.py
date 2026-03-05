import datetime
import shutil
import subprocess
import tempfile
from pathlib import Path

import semver
import yaml

from artemis.module_base import ArtemisBase


class BaseNewerVersionComparerModule(ArtemisBase):
    software_name: str

    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)

        self.endoflife_data_folder = tempfile.mkdtemp()
        try:
            subprocess.check_call(
                ["git", "clone", "https://github.com/endoflife-date/endoflife.date", self.endoflife_data_folder],
                timeout=60,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            shutil.rmtree(self.endoflife_data_folder, ignore_errors=True)
            raise RuntimeError(
                f"Failed to clone endoflife data repository: {e}. "
                "Check network connectivity to github.com."
            ) from e

        endoflife_data_path = Path(self.endoflife_data_folder) / "products" / (self.software_name + ".md")
        with open(endoflife_data_path, "r", encoding="utf-8") as f:
            self.endoflife_data = next(yaml.load_all(f, yaml.SafeLoader))

    def _parse_version(self, version: str) -> semver.VersionInfo:
        if version.count(".") == 1:
            return semver.VersionInfo.parse(version + ".0")
        else:
            return semver.VersionInfo.parse(version)

    def is_version_obsolete(
        self,
        version: str,
    ) -> bool:
        version_parsed = self._parse_version(version)

        for release in self.endoflife_data["releases"]:
            # We cannot just do "if not version.startswith(release["releaseCycle"])", because version 50 is not in the
            # "5" release cycle.
            if not (version == release["releaseCycle"] or version.startswith(release["releaseCycle"] + ".")):
                continue

            # Semver compare returns 1 if the latter version is greater, 0 if they are equal, and -1 if
            # the latter version is smaller.
            comparison_result = semver.VersionInfo.parse(release["latest"]).compare(version_parsed)
            if comparison_result > 0:
                return True
            elif comparison_result == 0:
                return release["eol"] <= datetime.datetime.now().date()  # type: ignore
            else:
                self.log.warning(
                    "Detected a newer version (%s) than newest for this cycle in https://github.com/endoflife-date (%s)",
                    version,
                    release["latest"],
                )
                return False

        return True  # if it's not even mentioned, let's consider it obsolete
