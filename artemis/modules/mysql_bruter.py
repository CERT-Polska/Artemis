#!/usr/bin/env python3
from typing import List, Tuple

import pymysql
from karton.core import Task
from pydantic import BaseModel

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.modules.data.common_sql_credentials import COMMON_SQL_CREDENTIALS
from artemis.task_utils import get_target_host

BRUTE_CREDENTIALS = COMMON_SQL_CREDENTIALS + [
    ("mysql", "mysql"),
    ("root", "MyNewPass"),
]


class MySQLBruterResult(BaseModel):
    credentials: List[Tuple[str, str]] = []


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class MySQLBruter(ArtemisBase):
    """
    Performs a brute force attack on MySQL servers to guess login and password.
    """

    identity = "mysql_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.MYSQL.value},
    ]

    def run(self, current_task: Task) -> None:
        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        result = MySQLBruterResult()

        for username, password in BRUTE_CREDENTIALS:
            try:
                self.throttle_request(lambda: pymysql.connect(host=host, port=port, user=username, password=password))
                result.credentials.append((username, password))
            except pymysql.err.OperationalError:
                pass

        if result.credentials:
            status = TaskStatus.INTERESTING
            status_reason = "Found working credentials for the MySQL server: " + ", ".join(
                sorted([username + ":" + password for username, password in result.credentials])
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    MySQLBruter().loop()
