#!/usr/bin/env python3
import re
from dataclasses import asdict, dataclass
from typing import List, Optional, Pattern

import requests
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisHTTPBase

RE_USER_AGENT = re.compile(r"^\s*user-agent:\s*(.*)", re.I)
RE_ALLOW = re.compile(r"^\s*allow:\s*(/.*)", re.I)
RE_DISALLOW = re.compile(r"^\s*disallow:\s*(/.*)", re.I)

NOT_INTERESTING_PATHS = [re.compile(p, re.I) for p in [r"/wp-admin/?.*", r"/wp-includes/?.*", "/", "/icons/"]]


@dataclass
class RobotsGroup:
    user_agents: List[str]
    allow: List[str]
    disallow: List[str]


@dataclass
class RobotsResult:
    status: int
    groups: List[RobotsGroup]


class RobotsScanner(ArtemisHTTPBase):
    """
    Looks for robots.txt file and finds disallowed and allowed paths
    """

    identity = "robots"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def _parse_rule(self, line: str, pattern: Pattern) -> Optional[str]:
        if match := re.match(pattern, line):
            return match.group(1).strip()  # type: ignore
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

    def _get_interesting_paths(self, result: RobotsResult) -> List[str]:
        if len(result.groups) == 0:
            return False

        # Iterate over all paths from all groups
        interesting_paths = []
        for g in result.groups:
            for path in g.allow + g.disallow:
                if not any([re.match(p, path) for p in NOT_INTERESTING_PATHS]):
                    interesting_paths.append(path)
        return interesting_paths

    def scan(self, url: str) -> RobotsResult:
        # Invalid certificate is probably more interesting then a valid one
        response = requests.get(f"{url}/robots.txt", verify=False, timeout=5, allow_redirects=False)

        result = RobotsResult(response.status_code, [])
        if result.status == 200:
            result.groups.extend(self._parse_robots(response.text))

        return result

    def run(self, current_task: Task) -> None:
        url = self.get_target_url(current_task)
        self.log.info(f"robots looking for {url}/robots.txt")

        result = self.scan(url)
        interesting_paths = self._get_interesting_paths(result)

        if interesting_paths:
            status = TaskStatus.INTERESTING
            status_reason = f"Found potentially interesting paths in robots.txt: {', '.join(interesting_paths)}"
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=asdict(result))


if __name__ == "__main__":
    RobotsScanner().loop()
