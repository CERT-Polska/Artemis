#!/usr/bin/env python3
from karton.core import Task
from artemis.resolvers import lookup, ResolutionException
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase

class DomainScanner(ArtemisBase):
    """
    DNS checker to verify if domains exist in the DNS system.
    """

    identity = "domain_scanner"
    filters = [
        {"type": TaskType.DOMAIN.value},
        {"type": TaskType.NEW.value},
    ]

    def check_domain_exists(self, domain: str) -> bool:
        try:
            # Check for NS records
            ns_records = lookup(domain, "NS")
            if ns_records:
                return True
            # If no NS records, check for A records
            a_records = lookup(domain, "A")
            return len(a_records) > 0
        except ResolutionException:
            return False

    def run(self, current_task: Task) -> None:
        domains = current_task.get_payload(TaskType.DOMAIN)
        if isinstance(domains, str):
            domains = [domains]

        existing_domains = []
        non_existing_domains = []

        for domain in domains:
            if self.check_domain_exists(domain):
                existing_domains.append(domain)
            else:
                non_existing_domains.append(domain)

        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.OK,
            data={
                "existing_domains": existing_domains,
                "non_existing_domains": non_existing_domains
            }
        )

        # Create a new task for existing domains
        if existing_domains:
            self.add_task(
            new_task=Task(
                    headers={
                        "type": TaskType.DOMAIN.value,
                    },
                    payload={
                        TaskType.DOMAIN.value: existing_domains
                    }
                )
            )
        # Log or handle non-existing domains
        if non_existing_domains:
            self.log.info(f"The following domains do not exist and will not be scanned: {non_existing_domains}")

if __name__ == "__main__":
    DomainScanner().loop()
