#!/usr/bin/env python3
import re
from dataclasses import asdict, dataclass
from typing import List, Optional, Pattern

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.models import FoundURL
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import is_directory_index

RE_USER_AGENT = re.compile(r"^\s*user-agent:\s*(.*)", re.I)
RE_ALLOW = re.compile(r"^\s*allow:\s*(/.*)", re.I)
RE_DISALLOW = re.compile(r"^\s*disallow:\s*(/.*)", re.I)

NOT_INTERESTING_PATHS = [re.compile(p, re.I) for p in [r"/wp-admin/?.*", r"/wp-includes/?.*", "^/$"]]


@dataclass
class RobotsGroup:
    user_agents: List[str]
    allow: List[str]
    disallow: List[str]


@dataclass
class RobotsResult:
    status: int
    groups: List[RobotsGroup]
    found_urls: List[FoundURL]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class RobotsScanner(ArtemisBase):
    """
    Looks for robots.txt file, emits a URL task for each found path and checks whether the paths have a directory index enabled.
    """

    identity = "robots"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _parse_rule(self, line: str, pattern: Pattern[str]) -> Optional[str]:
        if match := re.match(pattern, line):
            return match.group(1).strip()
        return None

    def _parse_robots(self, content: str) -> List[RobotsGroup]:
        groups: List[RobotsGroup] = list()
        current_group = RobotsGroup([], [], [])

        for line in content.splitlines():
            if agent_match := re.match(RE_USER_AGENT, line):
                if len(current_group.allow) > 0 or len(current_group.disallow) > 0:
                    groups.append(current_group)
                    current_group = RobotsGroup([], [], [])
                current_group.user_agents.append(agent_match.group(1))
            elif allow_path := self._parse_rule(line, RE_ALLOW):
                if len(current_group.user_agents) == 0:
                    raise ValueError("'allow' rule before startgroupline")
                current_group.allow.append(allow_path)
            elif disallow_path := self._parse_rule(line, RE_DISALLOW):
                if len(current_group.user_agents) == 0:
                    raise ValueError("'disallow' rule before startgroupline")
                current_group.disallow.append(disallow_path)

        if len(current_group.user_agents) > 0:
            groups.append(current_group)

        return groups

    def _download(self, current_task: Task, url: str, groups: List[RobotsGroup]) -> List[FoundURL]:
        if len(groups) == 0:
            return []

        # Iterate over all paths from all groups
        found_urls = []
        for g in groups:
            for path in g.allow + g.disallow:
                if not any([re.match(p, path) for p in NOT_INTERESTING_PATHS]):
                    if "*" in path:
                        continue

                    path = path.rstrip("$")

                    full_url = f"{url}{path}"
                    content = self.http_get(full_url).content
                    if is_directory_index(content):
                        found_urls.append(
                            FoundURL(
                                url=full_url,
                                content_prefix=content[: Config.Miscellaneous.CONTENT_PREFIX_SIZE],
                                has_directory_index=True,
                            )
                        )

                    new_task = Task(
                        {
                            "type": TaskType.URL,
                        },
                        payload={
                            "url": full_url,
                            "content": content,
                        },
                    )
                    self.add_task(current_task, new_task)
        return found_urls

    def download_robots(self, current_task: Task, url: str) -> RobotsResult:
        response = self.http_get(f"{url}/robots.txt", allow_redirects=False)

        groups = []
        if response.status_code == 200:
            groups.extend(self._parse_robots(response.text))

        result = RobotsResult(response.status_code, groups, self._download(current_task, url, groups))
        return result

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"robots looking for {url}/robots.txt")

        result = self.download_robots(current_task, url)

        if result.found_urls:
            status = TaskStatus.INTERESTING
            status_reason = (
                "Found potentially interesting paths (having directory index) in "
                f"robots.txt: {', '.join(sorted([item.url for item in result.found_urls]))}"
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(
            task=current_task, status=status, status_reason=status_reason, data={"result": asdict(result)}
        )


if __name__ == "__main__":
    RobotsScanner().loop()
