import dataclasses
import datetime
import json
from enum import Enum
from typing import Any

from sqlalchemy.orm import InstanceState  # type: ignore


class JSONEncoderAdditionalTypes(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        if isinstance(o, Enum):
            return o.value
        if isinstance(o, InstanceState):
            return None
        return super().default(o)
