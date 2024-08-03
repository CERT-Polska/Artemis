#!/usr/bin/env python3
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Set

from karton.core import Consumer, Task
from karton.core.config import Config as KartonConfig

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.db import DB
from artemis.domains import is_domain, is_subdomain
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error


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

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(db, *args, **kwargs)

        # before we migrate the tasks, let's create binds to make sure the new tasks will hit the queue of this module
        self.backend.register_bind(self._bind)

        with self.lock:
            old_modules = ["crtsh", "gau"]

            if len({bind.identity for bind in self.backend.get_binds()} & set(old_modules)) > 0:
                for old_task in self.backend.iter_all_tasks(parse_resources=False):
                    if old_task.receiver in old_modules and old_task.payload.get("source", None) != "migration":
                        self.log.info(f"Moving task from {old_task.receiver} to {self.identity}")
                        new_task = Task(
                            {"type": TaskType.DOMAIN.value},
                            payload={
                                "domain": old_task.payload["domain"],
                                "source": "migration",
                            },
                        )

                        self.add_task(old_task, new_task)
                        self.backend.delete_task(old_task)

                for old_module in old_modules:

                    class KartonDummy(Consumer):
                        """
                        This karton has been replaced with subdomain_enumeration.
                        """

                        identity = old_module
                        persistent = False
                        filters: List[Dict[str, Any]] = []

                        def process(self, task: Task) -> None:
                            pass

                    karton = KartonDummy(config=KartonConfig())
                    karton._shutdown = True
                    karton.loop()

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

        return set()  # this is an unreachable statement but the linter doesn't see that

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

    def get_subdomains_from_gau(self, domain: str) -> Optional[Set[str]]:
        return self.get_subdomains_from_tool(
            "gau",
            ["--subs"] + Config.Modules.SubdomainEnumeration.GAU_ADDITIONAL_OPTIONS,
            domain,
            input=domain.encode("idna"),
        )

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

        subdomain_tools = [
            self.get_subdomains_from_subfinder,
            self.get_subdomains_from_gau,
        ]

        for tool_func in subdomain_tools:
            try:
                subdomains_from_tool = self.get_subdomains_with_retry(tool_func, domain)
                self.log.info(f"Subdomains from {tool_func.__name__}: {subdomains_from_tool}")
            except UnableToObtainSubdomainsException as e:
                self.log.error(f"Failed to obtain subdomains from {tool_func.__name__} for domain {domain}: {e}")
                continue

            valid_subdomains_from_tool = set()
            for subdomain in subdomains_from_tool:
                subdomain = subdomain.strip(".")
                if not is_domain(subdomain):
                    self.log.info("Non-domain returned: %s from %s", subdomain, domain)
                    continue
                if not is_subdomain(subdomain, domain):
                    self.log.info("Non-subdomain returned: %s from %s", subdomain, domain)
                    continue
                if subdomain in valid_subdomains:
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
                if subdomain != domain:  # ensure we are not adding the parent domain again
                    task = Task(
                        {"type": TaskType.DOMAIN},
                        payload={
                            "domain": subdomain,
                        },
                    )
                    self.add_task_if_domain_exists(current_task, task)

            valid_subdomains.update(valid_subdomains_from_tool)

        if valid_subdomains:
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(valid_subdomains))
        else:
            self.log.error(f"Failed to obtain any subdomains for domain {domain}")
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR)
            return


if __name__ == "__main__":
    SubdomainEnumeration().loop()
