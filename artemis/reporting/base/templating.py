import os
from dataclasses import dataclass
from pathlib import Path

from .reporters import get_all_reporters


@dataclass
class ReportEmailTemplateFragment:
    content: str
    # The higher the priority, the earlier in the e-mail the fragment should be
    priority: int

    @staticmethod
    def from_file(path: str, priority: int) -> "ReportEmailTemplateFragment":
        with open(path, "r") as f:
            return ReportEmailTemplateFragment(content=f.read(), priority=priority)


def build_message_template() -> str:
    """
    Builds a message template from fragments provided by various reporters.
    """
    fragments = []
    for reporter in get_all_reporters():
        for fragment in reporter.get_email_template_fragments():
            # We sort by priority + name so that for a single priority, fragments from a single
            # reporter will be grouped together.
            fragments.append((fragment.priority, reporter.__name__, fragment.content))

    content_sum = ""
    for _, _, content in sorted(fragments, reverse=True):
        content_sum += content

    content_sum = (
        # the custom_definitions.jinja2 file may contain e.g. custom header or footer text and
        # be provided by a different module.
        _load_template(Path("custom_definitions.jinja2"), allow_nonexistent=True)
        + _load_template(Path("header.jinja2"))
        + content_sum
        + _load_template(Path("footer.jinja2"))
    )

    return content_sum


def _load_template(relative_path: Path, allow_nonexistent: bool = False) -> str:
    template_path = Path(os.path.dirname(__file__)) / ".." / "templates" / relative_path

    if allow_nonexistent and not os.path.exists(template_path):
        return ""

    with open(template_path) as f:
        return f.read()
