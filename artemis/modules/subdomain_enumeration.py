#!/usr/bin/env python3
import time
import urllib.parse
from typing import Callable, List, Optional, Set

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error


# NOTE: The rappidns, jldc, and crtsh modules were removed from this class
# as their functionality is already implemented internally by the subfinder and amass and gau utilities.
class UnableToObtainSubdomainsException(Exception):
    pass


class SubdomainEnumeration(ArtemisBase):
    """
    Consumes `type: domain` to gather subdomains and produces `type: domain`.
    """

    identity = "subdomain_enumeration"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]
    lock_target = False

    def get_subdomains_with_retry(
        self,
        func: Callable[[str], Optional[Set[str]]],
        domain: str,
        retries: int = Config.Modules.SubdomainEnumeration.RETRIES,
        sleep_time_seconds: int = Config.Modules.SubdomainEnumeration.SLEEP_TIME_SECONDS,
    ) -> Set[str]:
        for retry_id in range(retries):
            subdomains = func(domain)
            if subdomains is not None:
                return subdomains

            self.log.info("Retrying for domain %s", domain)
            if retry_id < retries - 1:
                time.sleep(sleep_time_seconds)
            else:
                raise UnableToObtainSubdomainsException(
                    f"Unable to obtain subdomains for {domain} after {retries} retries"
                )

        return set()

    def get_subdomains_from_tool(
        self, tool: str, args: List[str], domain: str, input: Optional[bytes] = None
    ) -> Optional[Set[str]]:
        subdomains: Set[str] = set()
        try:
            result = check_output_log_on_error([tool] + args, self.log, input=input)
            for item in result.decode().splitlines():
                if "://" in item:
                    url_parsed = urllib.parse.urlparse(item)
                    if not url_parsed.hostname:
                        continue
                    item = url_parsed.hostname

                subdomains.add(item)

            return subdomains
        except Exception:
            self.log.exception(f"Unable to obtain information from {tool} for domain {domain}")
            return None

    def get_subdomains_from_subfinder(self, domain: str) -> Optional[Set[str]]:
        return self.get_subdomains_from_tool("subfinder", ["-d", domain, "-silent", "-all", "-recursive"], domain)

    def get_subdomains_from_amass(self, domain: str) -> Optional[Set[str]]:
        return self.get_subdomains_from_tool("amass", ["enum", "-passive", "-d", domain, "-silent"], domain)

    def get_subdomains_from_gau(self, domain: str) -> Optional[Set[str]]:
        return self.get_subdomains_from_tool("gau", ["-subs"], domain, input=domain.encode("idna"))

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")
        encoded_domain = domain.encode("idna").decode("utf-8")

        if self.redis.get(f"subdomain-enumeration-done-{encoded_domain}"):
            self.log.info(
                "SubdomainEnumeration has already been performed for %s. Skipping further enumeration.", domain
            )
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        valid_subdomains = set()

        for f in [self.get_subdomains_from_subfinder, self.get_subdomains_from_amass, self.get_subdomains_from_gau]:
            try:
                subdomains_from_tool = self.get_subdomains_with_retry(f, domain)
                self.log.info(f"Subdomains from {f.__name__}: {subdomains_from_tool}")
            except UnableToObtainSubdomainsException as e:
                self.log.error(f"Failed to obtain subdomains from {f.__name__} for domain {domain}: {e}")

            valid_subdomains_from_tool = set()
            for subdomain in subdomains_from_tool:
                if not is_subdomain(subdomain, domain):
                    self.log.info("Non-subdomain returned: %s from %s", subdomain, domain)
                    continue
                valid_subdomains_from_tool.add(subdomain)

            # Batch mark subdomains as done in Redis using a pipeline
            with self.redis.pipeline() as pipe:
                for subdomain in valid_subdomains_from_tool:
                    encoded_subdomain = subdomain.encode("idna").decode("utf-8")
                    pipe.setex(
                        f"subdomain-enumeration-done-{encoded_subdomain}",
                        Config.Miscellaneous.SUBDOMAIN_ENUMERATION_TTL_DAYS * 24 * 60 * 60,
                        1,
                    )
                pipe.execute()

            # We save the task as soon as we have results from a single tool so that other kartons can do something.
            for subdomain in valid_subdomains_from_tool:
                task = Task(
                    {"type": TaskType.DOMAIN},
                    payload={
                        "domain": subdomain,
                    },
                )
                self.add_task(current_task, task)

            valid_subdomains.update(valid_subdomains_from_tool)

        if valid_subdomains:
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(valid_subdomains))
        else:
            self.log.error(f"Failed to obtain any subdomains for domain {domain}")
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR)
            return


if __name__ == "__main__":
    SubdomainEnumeration().loop()
