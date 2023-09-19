#!/usr/bin/env python3
import re
import string
import time
from typing import Optional, Set

import requests
from karton.core import Task
from psycopg2 import OperationalError, connect

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase

DOMAIN_REGEX = r"([a-z0-9\-]+\.)+[a-z0-9\-]+"


class UnableToObtainSubdomainsException(Exception):
    pass


class CrtshScanner(ArtemisBase):
    """
    Consumes `type: domain` and adds subdomains fetched from crt.sh
    Produces `type: domain`.
    """

    identity = "crtsh"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]
    # We don't ensure we're the only module touching the target, as actually we interact with crt.sh, not
    # the target. We lock crt.sh instead in the run() method.
    lock_target = False

    def query_sql(self, domain: str) -> Optional[Set[str]]:
        try:
            ct_domains: set[str] = set()
            conn = connect("postgresql://guest@crt.sh:5432/certwatch")
            conn.set_session(readonly=True, autocommit=True)
            with conn.cursor() as cursor:
                # Validate characters as we are putting the domain inside a LIKE query
                # Escaping LIKE queries is complex:
                # https://stackoverflow.com/questions/2106207/escape-sql-like-value-for-postgres-with-psycopg2
                # so for now let's just whitelist domain characters.
                assert all([c in string.ascii_letters + "-_" + string.digits + "." or ord(c) >= 0x80 for c in domain])
                cursor.execute(
                    (
                        "SELECT name_value FROM certificate_and_identities"
                        " WHERE plainto_tsquery('certwatch', %s) @@ identities(certificate)"
                        " AND name_value ILIKE %s"
                        " AND (name_type = '2.5.4.3' OR name_type = 'san:dNSName')"
                        " GROUP BY name_value"
                    ),
                    (domain, "%." + domain),
                )
                results = cursor.fetchall()

                for row in results:
                    (entry,) = row
                    if re.fullmatch(DOMAIN_REGEX, entry):
                        ct_domains.add(entry)
            conn.close()
            return ct_domains
        except OperationalError:
            return None

    def query_json(self, domain: str) -> Optional[Set[str]]:
        try:
            response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        except requests.exceptions.RequestException:
            self.log.exception("Unable to obtain information from crt.sh for domain %s", domain)
            return None

        if response.ok:
            ct_domains: set[str] = set()
            for cert in response.json():
                for entry in cert["name_value"].split("\n"):
                    if re.fullmatch(DOMAIN_REGEX, entry):
                        ct_domains.add(entry)
            return ct_domains
        else:
            return None

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")

        for skipped_domain in Config.Miscellaneous.DOMAINS_TO_SKIP_SUBDOMAIN_ENUMERATION:
            if is_subdomain(domain, skipped_domain):
                self.log.info("Skipping subdomain enumeration for %s, as it's a subdomain of %s", domain, skipped_domain)
                return

        if self.redis.get(f"crtsh-done-{domain}"):
            self.log.info(
                "Crtsh has already returned %s - and as it's a recursive query, no further query will be performed.",
                domain,
            )
            self.db.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        for retry_id in range(Config.Modules.Crtsh.CRTSH_NUM_RETRIES):
            ct_domains = self.query_sql(domain)

            if ct_domains is None:
                ct_domains = self.query_json(domain)

            if ct_domains is None:
                self.log.info("crtsh: retrying for domain %s", domain)
                if retry_id < Config.Modules.Crtsh.CRTSH_NUM_RETRIES - 1:
                    time.sleep(Config.Modules.Crtsh.CRTSH_SLEEP_ON_RETRY_SECONDS)
                else:
                    raise UnableToObtainSubdomainsException()
            else:
                break

        assert ct_domains is not None
        for entry in ct_domains:
            if not is_subdomain(entry, domain):
                # Sometimes crt.sh returns a certificate for both a subdomain and some other domain - let's
                # ignore these other domains.
                self.log.info("Non-subdomain returned: %s from %s", entry, domain)
                continue

            self.redis.setex(
                f"crtsh-done-{domain}", Config.Miscellaneous.SUBDOMAIN_ENUMERATION_TTL_DAYS * 24 * 60 * 60, 1
            )

            task = Task(
                {"type": TaskType.DOMAIN},
                payload={
                    "domain": entry,
                },
            )
            self.add_task(current_task, task)

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(ct_domains))
        self.log.info(f"Added {len(ct_domains)} subdomains to scan")


if __name__ == "__main__":
    CrtshScanner().loop()
