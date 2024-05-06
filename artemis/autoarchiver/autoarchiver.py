import datetime
import gzip
import json
import os
import pathlib
import time

from artemis import utils
from artemis.config import Config
from artemis.db import DB
from artemis.json_utils import JSONEncoderAdditionalTypes

db = DB()
LOGGER = utils.build_logger(__name__)


def archive_old_results() -> None:
    archive_age_timedelta = datetime.timedelta(seconds=Config.Data.Autoarchiver.AUTOARCHIVER_MIN_AGE_SECONDS)

    old_items = db.get_oldest_task_results_before(
        time_to=datetime.datetime.now() - archive_age_timedelta,
        max_length=Config.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE,
    )

    LOGGER.info("Found %s old items", len(old_items))

    if len(old_items) < Config.Data.Autoarchiver.AUTOARCHIVER_PACK_SIZE:
        LOGGER.info("Too small, not archiving")
        return

    date_from = old_items[0]["created_at"]
    date_to = old_items[-1]["created_at"]

    output_path = str(
        pathlib.Path(Config.Data.Autoarchiver.AUTOARCHIVER_OUTPUT_PATH)
        / (
            "%s-%s.json.gz"
            % (
                date_from.strftime("%Y-%m-%d_%H_%M_%S"),
                date_to.strftime("%Y-%m-%d_%H_%M_%S"),
            )
        )
    )

    LOGGER.info("Saving to %s", output_path)

    with gzip.open(output_path, "wt", encoding="utf-8") as f:
        json.dump(old_items, f, indent=4, cls=JSONEncoderAdditionalTypes)

    LOGGER.info("Saved %s megabytes", os.stat(output_path).st_size / (1024 * 1024 * 1.0))

    for item in old_items:
        db.delete_task_result(item["id"])

    LOGGER.info("Deleted %d documents", len(old_items))


def main() -> None:
    while True:
        LOGGER.info("Archiving old results...")
        archive_old_results()

        LOGGER.info("Sleeping %s seconds", Config.Data.Autoarchiver.AUTOARCHIVER_INTERVAL_SECONDS)
        time.sleep(Config.Data.Autoarchiver.AUTOARCHIVER_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
