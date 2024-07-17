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
    ]

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload(TaskType.DOMAIN)
        domain_exists = self.check_domain_exists(domain)

        if domain_exists:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                data={
                    "domain": domain,
                    "exists": True
                }
            )
            # Create a new task for the next module
            new_task = Task(
                {"type": TaskType.DOMAIN},
                payload={TaskType.DOMAIN: domain},
                payload_persistent={"domain_exists": True}
            )
            self.add_task(current_task, new_task)
        else:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Domain does not exist: {domain}",
                data={"domain": domain, "exists": False}
            )

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

if __name__ == "__main__":
    DomainScanner().loop()