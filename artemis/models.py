from dataclasses import dataclass


@dataclass
class FoundURL:
    url: str
    content_prefix: str
    has_directory_index: bool
