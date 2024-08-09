from enum import Enum
from typing import Any, Callable


class LoadRiskClass(str, Enum):
    LOW = "🟢 Scanned system load/risk: low."
    MEDIUM = "🟡 Scanned system load/risk: medium."
    HIGH = "🔴 Scanned system load/risk: high."


def load_risk_class(c: LoadRiskClass) -> Callable[[Any], Any]:
    def decorator(decorated_class: Any) -> Any:
        if decorated_class.__doc__:
            decorated_class.__doc__ = decorated_class.__doc__.strip() + "\n\n" + c.value
        else:
            decorated_class.__doc__ = c.value
        return decorated_class

    return decorator
