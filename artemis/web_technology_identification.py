import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

WAPPALYZER_PATH = "/opt/artemis/modules/utils/wappalyzer/"


@dataclass
class Technology:
    """A single technology detected by Wappalyzer on a URL.

    Wappalyzer reports the technology key as ``"Name:Version"`` when a version
    was extracted; we split it here so downstream code has structured access.
    """

    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    categories: List[str] = field(default_factory=list)


def _parse_tech(raw: Dict[str, Any]) -> Technology:
    raw_name = str(raw.get("name", ""))
    if ":" in raw_name:
        name, _, version = raw_name.partition(":")
    else:
        name, version = raw_name, None

    cpe = raw.get("cpe") or None
    raw_categories = raw.get("categories") or []
    if isinstance(raw_categories, list):
        categories = [str(c) for c in raw_categories]
    else:
        categories = []

    return Technology(
        name=name,
        version=version if version else None,
        cpe=str(cpe) if cpe else None,
        categories=categories,
    )


def run_tech_detection(urls: List[str], logger: logging.Logger) -> Dict[str, List[Technology]]:
    """
    Run technology detection on a list of URLs using Wappalyzer.

    Returns a mapping of URL -> list of detected technologies. On subprocess or
    JSON parse failure, returns an empty list per URL.
    """
    wappalyzer_path = os.path.join(os.path.dirname(__file__), "modules", "utils", "wappalyzer")
    main_go_path = os.path.join(wappalyzer_path, "main.go")
    if not os.path.exists(main_go_path):
        raise FileNotFoundError(f"Wappalyzer main.go not found at {main_go_path}")

    try:
        # Update the Wappalyzer package once
        subprocess.run(
            ["go", "-C", WAPPALYZER_PATH, "get", "-u", "./..."], cwd=wappalyzer_path, check=True, capture_output=True
        )

        with tempfile.NamedTemporaryFile(mode="w") as temp_file:
            for url in urls:
                temp_file.write(url + "\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())

            wappalyzer_output = subprocess.check_output(
                ["go", "run", main_go_path, temp_file.name], cwd=wappalyzer_path
            )

        raw = json.loads(wappalyzer_output)
        # Pre-seed every input URL so the result keeps the documented url -> list
        # contract even when Wappalyzer omits a URL it found nothing for (or choked
        # on); we then overlay whatever it did return.
        parsed: Dict[str, List[Technology]] = {url: [] for url in urls}
        for url, items in raw.items():
            if isinstance(items, list):
                parsed[url] = [_parse_tech(item) for item in items if isinstance(item, dict)]
        return parsed
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logger.error(f"Error running technology detection: {e}")
        return {url: [] for url in urls}


def to_tag_strings(techs: List[Technology]) -> List[str]:
    """Convert a list of ``Technology`` objects back to the legacy
    ``"Name:Version"`` form (just ``"Name"`` when no version is known).

    Used by callers that still operate on flat strings - primarily
    ``nuclei_router`` for its ``-etags`` substring matching.
    """
    return [f"{t.name}:{t.version}" if t.version else t.name for t in techs]
