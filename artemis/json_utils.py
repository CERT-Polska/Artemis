import dataclasses
import datetime
import json
from typing import Any


class JSONEncoderWithDataclasses(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        return super().default(o)
