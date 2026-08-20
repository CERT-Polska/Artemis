import datetime
import io
import json
import re
import tarfile
import urllib.request

from artemis import utils

logger = utils.build_logger(__name__)


def strip_version_and_sw_edition(cpe23: str) -> str:
    parts = cpe23.split(":")
    if len(parts) >= 6:
        parts[5] = "*"
    if len(parts) >= 10:
        parts[9] = "*"
    return ":".join(parts)


def download_cpe_map() -> dict[str, str]:
    URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"

    logger.info("Downloading CPE map...")
    req = urllib.request.Request(URL)
    with urllib.request.urlopen(req) as resp:
        compressed = resp.read()
    logger.info("Downloaded CPE map")

    feed = []
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(".json"):
                raw = tar.extractfile(member).read().decode("utf-8")  # type: ignore
                data = json.loads(raw)
                feed.extend(data["products"])

    slug_re = re.compile(r"wordpress\.org/plugins/([^/]+)/$", re.IGNORECASE)

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
