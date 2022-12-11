import dataclasses
import json
from typing import Any


class JSONEncoderWithDataclasses(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)
