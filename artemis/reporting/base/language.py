from enum import Enum
from pathlib import Path

with open(Path(__file__).parent.parent / "languages.txt") as f:
    Language = Enum("Language", {line.strip(): line.strip() for line in f})  # type: ignore
