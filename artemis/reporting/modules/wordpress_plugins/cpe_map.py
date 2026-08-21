import datetime
import json
import os
import re
import tarfile
import urllib.request

from artemis import utils

logger = utils.build_logger(__name__)

CPE_CACHE = os.path.join(os.path.dirname(__file__), ".cache", "cpe_map.json")


def strip_version_and_sw_edition(cpe23: str) -> str:
    parts = cpe23.split(":")
    if len(parts) >= 6:
        parts[5] = "*"
    if len(parts) >= 10:
        parts[9] = "*"
    return ":".join(parts)


def download_cpe_map_file() -> str:
    if os.path.exists(CPE_CACHE + ".done"):
        logger.info("Loading CPE map from cache")
        return CPE_CACHE

    URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"

    logger.info("Downloading CPE map...")
    req = urllib.request.Request(URL)
    with urllib.request.urlopen(req) as resp:
        compressed = resp.read()
    logger.info("Downloaded CPE map")

    os.makedirs(os.path.dirname(CPE_CACHE), exist_ok=True)
    with open(CPE_CACHE, "wb") as f:
        f.write(compressed)
    with open(CPE_CACHE + ".done", "w") as f:
        f.write("ok")

    return CPE_CACHE


def download_cpe_map() -> dict[str, str]:
    file_path = download_cpe_map_file()

    feed = []
    with open(file_path, "rb") as f:
        with tarfile.open(fileobj=f, mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".json"):
                    raw = tar.extractfile(member).read().decode("utf-8")  # type: ignore
                    data = json.loads(raw)
                    feed.extend(data["products"])

    slug_re = re.compile(r"wordpress\.org/plugins/([^/]+)/", re.IGNORECASE)

    slug_to_cpe = {}
    slug_to_dates: dict[str, datetime.datetime] = {}

    for entry in feed:
        cpe = entry["cpe"]
        if cpe["deprecated"]:
            continue
        found_slug = None
        for ref in cpe.get("refs", []):
            m = slug_re.search(ref["ref"])
            if m:
                found_slug = m.group(1).lower()
                break

        if found_slug:
            stripped_cpe = strip_version_and_sw_edition(cpe["cpeName"])
            if found_slug not in slug_to_dates or slug_to_dates[found_slug] < datetime.datetime.fromisoformat(
                cpe["created"]
            ):
                slug_to_dates[found_slug] = datetime.datetime.fromisoformat(cpe["created"])
                slug_to_cpe[found_slug] = stripped_cpe

    logger.info("Downloaded CPE map for %d plugins" % len(slug_to_cpe))
    return slug_to_cpe


if __name__ == "__main__":
    for slug, cpe in download_cpe_map().items():
        print(slug, cpe)
