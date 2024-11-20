#!/usr/bin/env python3
from typing import List, Tuple

import psycopg2
from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.modules.data.common_sql_credentials import COMMON_SQL_CREDENTIALS
from artemis.task_utils import get_target_host

BRUTE_CREDENTIALS = COMMON_SQL_CREDENTIALS + [
    ("postgresql", "postgresql"),
    ("postgres", "postgres"),
]


class PostgreSQLBruterResult(BaseModel):
    credentials: List[Tuple[str, str]] = []


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class PostgreSQLBruter(ArtemisBase):
    """
    Performs a brute force attack on PostgreSQL servers to guess login and password.
    """

    identity = "postgresql_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.POSTGRESQL.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        result = PostgreSQLBruterResult()

        for username, password in BRUTE_CREDENTIALS:
            try:
                self.throttle_request(lambda: psycopg2.connect(host=host, port=port, user=username, password=password))
                result.credentials.append((username, password))
            except psycopg2.OperationalError:
                pass

        if result.credentials:
            status = TaskStatus.INTERESTING
            status_reason = "Found working credentials for the PostgreSQL server: " + ", ".join(
                sorted([username + ":" + password for username, password in result.credentials])
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    PostgreSQLBruter().loop()
