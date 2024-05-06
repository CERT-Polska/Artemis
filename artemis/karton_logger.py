import datetime
import fcntl
from pathlib import Path
from typing import Any, Dict

from karton.core.karton import LogConsumer


class FileLogger(LogConsumer):
    identity = "file-logger"
    opened_file = None
    opened_file_date = None

    def process_log(self, event: Dict[str, Any]) -> None:
        if event.get("type") == "log":

            if not self.opened_file or self.opened_file_date != datetime.datetime.now().date():
                if self.opened_file:
                    self.opened_file.close()
                self.opened_file_date = datetime.datetime.now().date()
                self.opened_file = open(Path("/karton-logs") / f"{self.opened_file_date.strftime('%Y-%m-%d')}.log", "w")
                # There should be one instance of the consumer, but for extra safety let's lock the file.
                # From the documentation (https://docs.python.org/3/library/fcntl.html):
                # "If LOCK_NB is used and the lock cannot be acquired, an OSError will be raised"
                # From https://www.gnu.org/software/libc/manual/html_node/File-Locks.html: "locks are released
                # when a process exits".
                fcntl.lockf(self.opened_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.opened_file.write(f"{event['name']}: {event['message']}\n")
            self.opened_file.flush()


if __name__ == "__main__":
    FileLogger().loop()
