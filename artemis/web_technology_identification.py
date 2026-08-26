import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class TechDetectionFailedException(Exception):
    """Raised when technology detection couldn't be performed at all.

    This is not the same as detecting no technologies - see the comment in run_tech_detection.
    """


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

    if name == "Basic":
        name = "Basic Auth"

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

    Returns a mapping of URL -> list of detected technologies. A URL that couldn't be fetched maps to an
    empty list, same as one that runs nothing we recognize.

    Raises TechDetectionFailedException if the detection itself couldn't be performed - the caller must not
    confuse that with a target running no technologies.
    """
    wappalyzer_path = os.path.join(os.path.dirname(__file__), "modules", "utils", "wappalyzer")
    main_go_path = os.path.join(wappalyzer_path, "main.go")
    if not os.path.exists(main_go_path):
        # Same class of failure as the ones below, so it gets the same exception - a caller catching
        # TechDetectionFailedException would otherwise miss this one.
        raise TechDetectionFailedException(f"Wappalyzer main.go not found at {main_go_path}")

    try:
        # The wappalyzergo version comes from go.mod. We deliberately don't upgrade it here: doing that on
        # each call meant production, CI and the pinned version were all running different code, so a broken
        # upstream release would hit production and CI at the same moment, with no PR to revert. Upgrades
        # arrive as Dependabot pull requests instead - see .github/dependabot.yml.
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
        # Returning an empty result here would be indistinguishable from "we checked and found nothing",
        # which is a lie the callers can't detect. Raising makes ArtemisBase retry the task and, if that
        # doesn't help, save it with TaskStatus.ERROR instead of recording a false negative.
        #
        # A target that didn't respond doesn't end up here - the wrapper logs that and exits with 0 - so this
        # means the detection itself is broken (no Go toolchain, no module, unreachable proxy, invalid output).
        logger.error(f"Error running technology detection: {e}")
        raise TechDetectionFailedException(f"Unable to run technology detection for {urls}") from e


def to_tag_strings(techs: List[Technology]) -> List[str]:
    """Convert a list of ``Technology`` objects back to the legacy
    ``"Name:Version"`` form (just ``"Name"`` when no version is known).

    Used by callers that still operate on flat strings - primarily
    ``nuclei_router`` for its ``-etags`` substring matching.
    """
    return [f"{t.name}:{t.version}" if t.version else t.name for t in techs]
