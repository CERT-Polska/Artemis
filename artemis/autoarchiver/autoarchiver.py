import datetime
import gzip
import json
import os
import pathlib
import time
from typing import Any, Iterator

from artemis import utils
from artemis.config import Config
from artemis.db import DB
from artemis.json_utils import JSONEncoderAdditionalTypes

db = DB()
LOGGER = utils.build_logger(__name__)


def _save_and_delete_items(items: Iterator[dict[str, Any]], path_suffix: str) -> int:
    output_dir = pathlib.Path(Config.Data.Autoarchiver.AUTOARCHIVER_OUTPUT_PATH)
    temp_path = str(
        output_dir / ("tmp_%s%s.json.gz" % (datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S_%f"), path_suffix))
    )

    ids: list[str] = []
    date_from: datetime.datetime | None = None
    date_to: datetime.datetime | None = None

    try:
        with gzip.open(temp_path, "wt", encoding="utf-8") as f:
            f.write("[\n")
            for i, item in enumerate(items):
                if date_from is None:
                    date_from = item["created_at"]
                if date_to is None or date_to < item["created_at"]:
                    date_to = item["created_at"]
                if i > 0:
                    f.write(",\n")
                f.write(json.dumps(item, indent=4, cls=JSONEncoderAdditionalTypes))
                ids.append(str(item["id"]))
            f.write("\n]")
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

    if date_from is None or date_to is None:
        LOGGER.warning("Coudln't properly extract date range.")
        return 0

    output_path = str(
        output_dir
        / (
            "%s-%s%s.json.gz"
            % (
                date_from.strftime("%Y-%m-%d_%H_%M_%S"),
                date_to.strftime("%Y-%m-%d_%H_%M_%S"),
                path_suffix,
            )
        )
    )
    os.rename(temp_path, output_path)
    LOGGER.info("Saving to %s", output_path)
    LOGGER.info("Saved %s megabytes", os.stat(output_path).st_size / (1024 * 1024 * 1.0))

    db.delete_task_results_by_ids(ids)
    LOGGER.info("Deleted %d documents", len(ids))

    return len(ids)


def archive_tag(tag: str) -> int:
    return _save_and_delete_items(
        db.iter_oldest_task_results_with_tag(
            tag=tag,
            max_length=Config.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE,
        ),
        "_tag_" + tag,
    )


def archive_old_results(interesting: bool) -> None:
    if interesting:
        archive_age_timedelta = datetime.timedelta(
            seconds=Config.Data.Autoarchiver.AUTOARCHIVER_MIN_AGE_SECONDS_INTERESTING
        )
    else:
        archive_age_timedelta = datetime.timedelta(
            seconds=Config.Data.Autoarchiver.AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING
        )

    time_to = datetime.datetime.now() - archive_age_timedelta
    count = db.count_oldest_task_results_before(
        time_to=time_to,
        max_length=Config.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE,
        interesting=interesting,
    )
    if count < Config.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE:
        LOGGER.info("Too small (%d items), not archiving", count)
        return

    _save_and_delete_items(
        db.iter_oldest_task_results_before(
            time_to=time_to,
            max_length=Config.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE,
            interesting=interesting,
        ),
        "_interesting" if interesting else "_not_interesting",
    )


def main() -> None:
    try:
        LOGGER.info("Archiving tags that need to be archived...")
        for item in db.list_tag_archive_requests(
            min_age=datetime.datetime.now()
            - datetime.timedelta(seconds=Config.Data.Autoarchiver.AUTOARCHIVER_TAG_ARCHIVE_MIN_AGE_SECONDS)
        ):
            tag = item["tag"]
            LOGGER.info(f"Archiving tag {tag}")
            num_items_archived = archive_tag(tag)
            if num_items_archived == 0:  # maybe more batches
                db.delete_tag_archive_request(tag)

        LOGGER.info("Archiving old results...")
        archive_old_results(True)
        archive_old_results(False)
    except Exception:
        LOGGER.exception("Error during archiving, will retry")

    LOGGER.info("Sleeping %s seconds", Config.Data.Autoarchiver.AUTOARCHIVER_INTERVAL_SECONDS)
    time.sleep(Config.Data.Autoarchiver.AUTOARCHIVER_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
