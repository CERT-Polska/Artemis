#!/usr/bin/env python3
import urllib.parse

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error


class GAU(ArtemisBase):
    """
    Consumes `type: domain` and adds subdomains fetched from AlienVault's Open Threat Exchange, the Wayback Machine,
    and Common Crawl using https://github.com/lc/gau. Produces `type: domain`.
    """

    identity = "gau"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]
    # We don't ensure we're the only module touching the target, as actually we interact with the providers, not
    # the target. We lock the providers instead in the run() method.
    lock_target = False

    def run(self, current_task: Task) -> None:
        if current_task.get_payload("tag") == "oswiata":
            self.log.info("skipping oswiata")
            return

        domain = current_task.get_payload("domain")
        with self.lock:
            output = check_output_log_on_error(
                [
                    "gau",
                ]
                + Config.Modules.Gau.GAU_ADDITIONAL_OPTIONS,
                self.log,
                input=domain.encode("idna"),
            )

            domains = set()
            for line in output.decode("ascii", errors="ignore").splitlines():
                url_parsed = urllib.parse.urlparse(line)
                if not url_parsed.hostname:
                    continue

                if is_subdomain(url_parsed.hostname, domain):
                    domains.add(url_parsed.hostname)

            for domain in domains:
                task = Task(
                    {"type": TaskType.DOMAIN},
                    payload={
                        "domain": domain,
                    },
                )
                self.add_task(current_task, task)

            self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(domains))
            self.log.info(f"Added {len(domains)} subdomains to scan")


if __name__ == "__main__":
    GAU().loop()
