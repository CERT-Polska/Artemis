#!/usr/bin/env python3
import re
from typing import List, NamedTuple

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

GIT_MAGIC = [
    r"^(ref:.*|[0-9a-f]{40}$)",
]

SVN_MAGIC = [
    "SQLite",
]

HG_MAGIC = [
    "\u0000\u0000\u0000\u0001",
    "\u0000\u0001\u0000\u0001",
    "\u0000\u0002\u0000\u0001",
    "\u0000\u0003\u0000\u0001",
]


class VCSConfig(NamedTuple):
    name: str
    path: str
    magic: List[str]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class VCSScanner(ArtemisBase):
    """
    Tries to find exposed git/SVN/Mercurial repositories.
    """

    identity = "vcs"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _detect_vcs(self, url: str, path: str, patterns: List[str]) -> bool:
        target = f"{url}/{path}"
        self.log.info(f"Testing {target}")
        response = self.http_get(target, allow_redirects=False)

        if response.status_code != 200:
            self.log.info(f"{target} does not exist")
            return False

        for pattern in patterns:
            if re.match(pattern, response.text.strip()):
                self.log.info(f"{target} found open repo!")
                return True

        self.log.info(f"{target} is not what we're looking for")
        return False

    def scan(self, current_task: Task, url: str) -> None:
        configs: List[VCSConfig] = [
            VCSConfig(name="git", path=".git/HEAD", magic=GIT_MAGIC),
            VCSConfig(name="svn", path=".svn/wc.db", magic=SVN_MAGIC),
            VCSConfig(name="hg", path=".gh/store/00manifest.i", magic=HG_MAGIC),
        ]
        result = {}
        found_vcs_descriptions = []

        for cfg in configs:
            vcs_found = self._detect_vcs(url, cfg.path, cfg.magic)
            result[cfg.name] = vcs_found
            if vcs_found:
                found_vcs_descriptions.append(cfg.name)

        if len(found_vcs_descriptions) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found version control system data: " + ", ".join(sorted(found_vcs_descriptions))
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"VCSScanner scanning {url}")

        self.scan(current_task, url)


if __name__ == "__main__":
    VCSScanner().loop()
