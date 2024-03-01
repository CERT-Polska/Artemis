import dataclasses
import datetime
import json
from typing import Any
from sqlalchemy.orm import InstanceState


class JSONEncoderAdditionalTypes(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        if isinstance(o, InstanceState):
            return None
        return super().default(o)
