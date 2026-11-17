import datetime
import os
import subprocess
import sys
import time
import uuid
from test.e2e.base import BaseE2ETestCase
from typing import List
from unittest.mock import patch

from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.task import Task, TaskPriority, TaskState

import artemis.cleanup
from artemis.binds import TaskType
from artemis.db import DB, Analysis

# The stack's Karton services use test-redis (docker/karton-test.ini), but this container is
# mounted with docker/karton.ini, which points at a different Redis - we use Karton's env
# overrides (which take precedence over the config files) to point at the stack's Redis.
KARTON_ENV = {"KARTON_REDIS_HOST": "test-redis", "KARTON_REDIS_PORT": "6379", "KARTON_REDIS_DB": "0"}

# Values for the karton-system instance spawned by this test (see setUp). The deadline is ~4x the
# worst case (process startup + task_crashed_timeout + one gc_interval), so a healthy stack
# garbage-collects the task in ~16 seconds.
GC_INTERVAL_SECONDS = 5
GC_TASK_CRASHED_TIMEOUT_SECONDS = 10
GC_DEADLINE_SECONDS = 60


class CrashedTaskGcE2ETestCase(BaseE2ETestCase):
    def setUp(self) -> None:
        super().setUp()
        # The stack's own karton-system runs with the production values (garbage collection every
        # 14400 seconds, task_crashed_timeout of 3 days), which is too slow to wait for in a test.
        # Instead of configuring it globally, we spawn our own instance against the same Redis,
        # with routing disabled not to interfere with the stack.
        self._gc_process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "karton.system",
                "--setup-bucket",
                "--disable-router",
                "--gc-interval",
                str(GC_INTERVAL_SECONDS),
                "--task-crashed-timeout",
                str(GC_TASK_CRASHED_TIMEOUT_SECONDS),
            ],
            env={**os.environ, **KARTON_ENV},
            stdout=subprocess.DEVNULL,
        )

    def tearDown(self) -> None:
        self._gc_process.terminate()
        self._gc_process.wait(timeout=10)

    def test_analysis_finished_only_after_karton_gced_its_crashed_tasks(self) -> None:
        """
        Scenario (all times relative to the start of the test):

        1. Insert one analysis older than MIN_ANALYSIS_AGE_TO_BE_CONSIDERED_FINISHED
           (created_at 2 days ago) directly into the database, and give it a single Karton task
           with status CRASHED - as if a module crashed while processing it.
        2. A cleanup pass run at this point must not finish the analysis, because crashed tasks
           count as pending.
        3. Restart the crashed task. The original task becomes FINISHED (so the garbage collector
           removes it) and the forked task is SPAWNED - the analysis must stay unfinished and
           the garbage collector must not remove the fork.
        4. Making the forked task crash as well gets it garbage-collected the same way,
           ~task_crashed_timeout (10s) + ~gc_interval (5s) later. Nothing else removes tasks
           within this time - Artemis's own _cleanup_tasks_not_in_queues removes tasks only
           after 3 days.
        5. A cleanup pass run after that marks the analysis finished. No task of the analysis
           remains, so nothing can be restarted into a finished analysis.
        """
        with patch.dict(os.environ, KARTON_ENV):
            db = DB()
            analysis_id = "test-analysis-" + uuid.uuid4().hex
            with db.session() as session:
                session.add(
                    Analysis(
                        id=analysis_id,
                        created_at=datetime.datetime.now() - datetime.timedelta(days=2),
                        target="test-target",
                        tag="crashed-task-gc-test",
                        stopped=False,
                        disabled_modules="",
                        priority=TaskPriority.NORMAL,
                        desired_priority=TaskPriority.NORMAL,
                    )
                )
                session.commit()

            backend = KartonBackend(config=KartonConfig())
            crashed_task = Task(
                {"type": TaskType.DOMAIN, "receiver": "crashed-task-gc-test-module"},
                payload={"domain": "test-target"},
                priority=TaskPriority.NORMAL,
                root_uid=analysis_id,
            )
            backend.register_task(crashed_task)
            backend.set_task_status(crashed_task, TaskState.CRASHED)

            def tasks_of_analysis() -> List[Task]:
                return [task for task in backend.iter_all_tasks() if task.root_uid == analysis_id]

            artemis.cleanup._update_analysis_finished_times()
            analysis = db.get_analysis_by_id(analysis_id)
            assert analysis is not None
            self.assertIsNone(analysis["finished_at"])

            restarted_task = backend.restart_task(crashed_task)
            artemis.cleanup._update_analysis_finished_times()
            analysis = db.get_analysis_by_id(analysis_id)
            assert analysis is not None
            self.assertIsNone(analysis["finished_at"])

            for _ in range(GC_DEADLINE_SECONDS // 2):
                if [task.uid for task in tasks_of_analysis()] == [restarted_task.uid]:
                    break
                time.sleep(2)
            self.assertEqual(
                [task.uid for task in tasks_of_analysis()],
                [restarted_task.uid],
                "the garbage collector removed the restarted task",
            )

            backend.set_task_status(restarted_task, TaskState.CRASHED)
            for _ in range(GC_DEADLINE_SECONDS // 2):
                if not tasks_of_analysis():
                    break
                time.sleep(2)
            self.assertEqual(tasks_of_analysis(), [], "karton-system did not garbage-collect the crashed task")

            artemis.cleanup._update_analysis_finished_times()
            analysis = db.get_analysis_by_id(analysis_id)
            assert analysis is not None
            self.assertIsNotNone(analysis["finished_at"])
