import datetime
import json
import subprocess
import tempfile
from pathlib import Path

import pytz
import semver

from artemis.config import Config
from artemis.module_base import ArtemisBase


class BaseNewerVersionComparerModule(ArtemisBase):
    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)

        self.release_data_folder = tempfile.mkdtemp()
        subprocess.call(["git", "clone", "https://github.com/endoflife-date/release-data", self.release_data_folder])

    def is_newer_version_available(
        self,
        version: str,
        require_same_major_version: bool,
        software_name: str,
        age_threshold_days: int = Config.Miscellaneous.VERSION_COMPARER_VERSION_AGE_DAYS,
    ) -> bool:
        release_data_path = Path(self.release_data_folder) / "releases" / (software_name + ".json")
        with open(release_data_path, "r") as f:
            release_data = json.load(f)

        version_parsed = semver.VersionInfo.parse(version)

        is_newer_version_available = False
        for release_version, release_date in release_data.items():
            release_version_parsed = semver.VersionInfo.parse(release_version)
            have_same_major_version = release_version_parsed.major == version_parsed.major

            # Semver compare returns 1 if the latter version is greater, 0 if they are equal, and -1 if
            # the latter version is smaller.
            is_release_newer = release_version_parsed.compare(version_parsed) > 0
            if (have_same_major_version or not require_same_major_version) and is_release_newer:
                version_age = datetime.datetime.now() - datetime.datetime.strptime(
                    release_date,
                    "%Y-%m-%d",
                )
                if version_age.days > age_threshold_days:
                    is_newer_version_available = True

        return is_newer_version_available
