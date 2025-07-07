import random
from test.base import KartonBackendMockWithRedis

from karton.core import Task
from karton.core.test import ConfigMock, KartonTestCase

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.db import DB, TestDB
from artemis.module_base import ArtemisBase


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class FlakyModuleRaisingException(ArtemisBase):
    """
    A flaky module that sometimes raises an exception.
    """

    identity = "flaky_module_raising_exception"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    num_retries = 100

    def run(self, current_task: Task) -> None:
        if random.randint(1, 100) < 90:
            raise Exception("a problem has occured")

        self.db.save_task_result(
            task=current_task, status=TaskStatus.INTERESTING, status_reason="Found a vulnerability"
        )


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class FlakyModuleSavingError(ArtemisBase):
    """
    A flaky module that sometimes raises an exception.
    """

    identity = "flaky_module_raising_exception"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    num_retries = 100

    def run(self, current_task: Task) -> None:
        if random.randint(1, 100) < 90:
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR)
            return

        self.db.save_task_result(
            task=current_task, status=TaskStatus.INTERESTING, status_reason="Found a vulnerability"
        )


class FlakyModuleRaisingExceptionTest(KartonTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = FlakyModuleRaisingException  # type: ignore

    def test_raising_exception(self) -> None:
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=DB()  # type: ignore
        )
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP},
            payload={"host": "cert.pl", "port": 80},
        )
        test_db = TestDB()
        test_db.delete_task_results()
        self.run_task(task)
        result = test_db.get_single_task_result()
        self.assertEqual(result["status"], "INTERESTING")
        self.assertEqual(result["status_reason"], "Found a vulnerability")


class FlakyModuleSavingErrorTest(KartonTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = FlakyModuleSavingError  # type: ignore

    def test_saving_error(self) -> None:
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=DB()  # type: ignore
        )
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP},
            payload={"host": "cert.pl", "port": 80},
        )
        test_db = TestDB()
        test_db.delete_task_results()
        self.run_task(task)
        result = test_db.get_single_task_result()
        self.assertEqual(result["status"], "INTERESTING")
        self.assertEqual(result["status_reason"], "Found a vulnerability")
