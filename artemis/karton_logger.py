import datetime
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
            self.opened_file.write(f"{event['name']}: {event['message']}\n")
            self.opened_file.flush()


if __name__ == "__main__":
    FileLogger().loop()
