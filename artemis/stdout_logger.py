import sys
from typing import Any, Dict

from karton.core.karton import LogConsumer


class StdoutLogger(LogConsumer):
    identity = "stdout-logger"

    def process_log(self, event: Dict[str, Any]) -> None:
        if event.get("type") == "log":
            print(f"{event['name']}: {event['message']}", file=sys.stderr)


if __name__ == "__main__":
    StdoutLogger().loop()
