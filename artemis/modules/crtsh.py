#!/usr/bin/env python3
import re
import string

import requests
from karton.core import Task
from psycopg2 import OperationalError, connect

from artemis.binds import TaskStatus, TaskType
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase

DOMAIN_REGEX = r"([a-z0-9\-]+\.)+[a-z0-9\-]+"


class CrtshScanner(ArtemisBase):
    """
    Consumes `type: domain` and adds subdomains fetched from crt.sh
    Produces `type: new`
    """

    identity = "crtsh"
    filters = [
        {"type": TaskType.DOMAIN},
    ]

    def query_sql(self, domain: str) -> set[str]:
        ct_domains: set[str] = set()
        conn = connect("postgresql://guest@crt.sh:5432/certwatch")
        conn.set_session(readonly=True, autocommit=True)
        with conn.cursor() as cursor:
            # Validate characters as we are putting the domain inside a SQL query
            assert all([c in string.ascii_letters + "-" + string.digits + "." for c in domain])
            cursor.execute(
                (
                    f"SELECT name_value FROM certificate_and_identities"
                    f" WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(certificate)"
                    f" AND name_value ILIKE '%.{domain}'"
                    f" AND (name_type = '2.5.4.3' OR name_type = 'san:dNSName')"
                    f" GROUP BY name_value"
                )
            )
            results = cursor.fetchall()

            for row in results:
                for entry in row:
                    if re.fullmatch(DOMAIN_REGEX, entry):
                        ct_domains.add(entry)
        conn.close()
        return ct_domains

    def query_json(self, domain: str) -> set[str]:
        ct_domains: set[str] = set()
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        if response.ok:
            for cert in response.json():
                for entry in cert["name_value"].split("\n"):
                    if re.fullmatch(DOMAIN_REGEX, entry):
                        ct_domains.add(entry)
        return ct_domains

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")
        with self.lock:
            try:
                ct_domains = self.query_sql(domain)
            except OperationalError:
                ct_domains = self.query_json(domain)
            for entry in ct_domains:
                assert is_subdomain(entry, domain)
                task = Task(
                    {"type": TaskType.NEW},
                    payload={
                        "data": entry,
                    },
                )
                self.add_task(current_task, task)

            self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=list(ct_domains))
            self.log.info(f"Added {len(ct_domains)} subdomains to scan")


if __name__ == "__main__":
    CrtshScanner().loop()
