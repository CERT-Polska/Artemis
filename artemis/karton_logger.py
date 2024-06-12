import datetime
import fcntl
import os
import subprocess
from pathlib import Path
from typing import Any, Dict

from karton.core.karton import LogConsumer

from artemis.config import Config

LOGS_PATH = Path("/karton-logs")
LOG_DATE_FORMAT = "%Y-%m-%d"


class FileLogger(LogConsumer):
    identity = "file-logger"
    opened_file = None
    opened_file_date = None

    def process_log(self, event: Dict[str, Any]) -> None:
        if event.get("type") == "log":

            if not self.opened_file or self.opened_file_date != datetime.datetime.now().date():
                if self.opened_file:
                    self.opened_file.close()
                self._rotate_logs()
                self.opened_file_date = datetime.datetime.now().date()
                self.opened_file = open(LOGS_PATH / f"{self.opened_file_date.strftime(LOG_DATE_FORMAT)}.log", "w")
                # There should be one instance of the consumer, but for extra safety let's lock the file.
                # From the documentation (https://docs.python.org/3/library/fcntl.html):
                # "If LOCK_NB is used and the lock cannot be acquired, an OSError will be raised"
                # From https://www.gnu.org/software/libc/manual/html_node/File-Locks.html: "locks are released
                # when a process exits".
                fcntl.lockf(self.opened_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.opened_file.write(f"{event['name']}: {event['message']}\n")
            self.opened_file.flush()

    def _rotate_logs(self) -> None:
        for file_name in os.listdir(LOGS_PATH):
            log_date_str, _ = tuple(file_name.split(".", 1))
            log_date = datetime.datetime.strptime(log_date_str, LOG_DATE_FORMAT).date()

            if (
                log_date
                < (
                    datetime.datetime.now() - datetime.timedelta(days=Config.Miscellaneous.REMOVE_LOGS_AFTER_DAYS)
                ).date()
            ):
                try:
                    os.unlink(LOGS_PATH / file_name)
                except OSError:
                    pass
                continue

            if log_date != datetime.datetime.now().date() and not file_name.endswith("gz"):
                with open(LOGS_PATH / file_name, "a") as f:
                    try:
                        fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError:
                        # Do nothing if failed to acquire the lock
                        continue
                    subprocess.call(["gzip", LOGS_PATH / file_name])


if __name__ == "__main__":
    FileLogger().loop()
