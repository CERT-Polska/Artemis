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
                assert all([c in string.ascii_letters + "-" + string.digits + "." for c in domain])
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
                    for entry in row:
                        if re.fullmatch(DOMAIN_REGEX, entry):
                            ct_domains.add(entry)
            conn.close()
            return ct_domains
        except OperationalError:
            return None

    def query_json(self, domain: str) -> Optional[Set[str]]:
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
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
        with self.lock:
            for retry_id in range(Config.CRTSH_NUM_RETRIES):
                ct_domains = self.query_sql(domain)

                if ct_domains is None:
                    ct_domains = self.query_json(domain)

                if ct_domains is None:
                    self.log.info("crtsh: retrying for domain %s", domain)
                    if retry_id < Config.CRTSH_NUM_RETRIES - 1:
                        time.sleep(Config.CRTSH_SLEEP_ON_RETRY_SECONDS)
                    else:
                        raise UnableToObtainSubdomainsException()

            assert ct_domains is not None
            for entry in ct_domains:
                assert is_subdomain(entry, domain), f"Non-subdomain returned: {entry} from {domain}"
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
