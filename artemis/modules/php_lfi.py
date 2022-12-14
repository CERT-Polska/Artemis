#!/usr/bin/env python3
import dataclasses
import re
from typing import Dict, List

from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisSingleTaskBase
from artemis.task_utils import get_target_url

LFI_REGEX = r"(({url})?/)?([a-zA-Z0-9-_]+).php\?([a-zA-Z-_]+)=[a-zA-Z0-9-_]+"
B64_FILTER = "php://filter/convert.base64-encode/resource="
B64_COMMON_PHP = r".*(PD9waHA|PD9QSFA|PCFET0NUWVBFIEhUTUw\+|PGh0bWw\+).*"


@dataclasses.dataclass
class LFICandidate:
    file: str
    param: str


def get_lfi_candidates(url: str, response_text: str) -> List[LFICandidate]:
    result = []
    for i in re.split("'|\"|>| ", response_text.replace("\n", "").replace("href=", "").replace("src=", "")):
        if match := re.match(LFI_REGEX.format(url=url), i):
            file = match.group(3)
            param = match.group(4)
            result.append(LFICandidate(file=file, param=param))
    return result


class PHPLFIScanner(ArtemisSingleTaskBase):
    """
    Tries to detect and verify PHP LFI
    """

    identity = "php_lfi"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    def scan(self, current_task: Task, url: str) -> None:
        found_lfi_descriptions = []
        result: Dict[str, str] = {}
        response = http_requests.get(url)

        if response.status_code != 200:
            self.log.info("{url} does not exist".format(url=url))
            return

        for candidate in get_lfi_candidates(url, response.text):
            key = f"file={candidate.file}.php, param_name={candidate.param}"
            if key not in result:
                self.log.info(
                    "checking for the presence of LFI in {url}/{file}.php?{param}=".format(
                        url=url, file=candidate.file, param=candidate.param
                    )
                )
                # We don't treat LFI candidates as interesting, only confirmed LFIs, to decrease the
                # amount of false positives.
                result[key] = "possible"

                for extension in ["", ".php"]:
                    lfi_test_url = "{url}/{file}.php?{param}={zfilter}{file}{extension}".format(
                        url=url,
                        file=candidate.file,
                        param=candidate.param,
                        zfilter=B64_FILTER,
                        extension=extension,
                    )
                    response = http_requests.get(lfi_test_url, allow_redirects=False)
                    if response.status_code == 200 and re.match(B64_COMMON_PHP, response.text.replace("\n", "")):
                        self.log.info("LFI is exploitable")
                        result[key] = "confirmed"

                        found_lfi_descriptions.append(lfi_test_url)

        if len(found_lfi_descriptions) > 0:
            status = TaskStatus.INTERESTING
            status_reason = "Found LFIs in " + ", ".join(sorted(found_lfi_descriptions))
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"php lfi scanning {url}")

        self.scan(current_task, url)


if __name__ == "__main__":
    PHPLFIScanner().loop()
