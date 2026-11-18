#!/usr/bin/env python3
"""Reproduces: when Katana times out, crawl-based detectors report TaskStatus.OK
instead of surfacing an error (see test/repro/README.md).

Runs in the test container; no image rebuild needed - this file rides the ./test mount:

    docker compose -f docker-compose.test.yaml run --rm -e KATANA_TIMEOUT_SECONDS=10 \
        test python3 /opt/test/repro/katana_timeout_returns_ok.py
"""

import os
import sys
from typing import cast

sys.path.insert(0, "/opt")

from test.base import ArtemisModuleTestCase  # noqa: E402

from karton.core import Task  # noqa: E402

from artemis.binds import Service, TaskStatus, TaskType  # noqa: E402
from artemis.modules.lfi_detector import LFIDetector  # noqa: E402

SHADOW_DIR = "/tmp/katana-shadow"


class Repro(ArtemisModuleTestCase):
    karton_class = LFIDetector  # type: ignore

    def run_detector(self) -> TaskStatus:
        self.setUp()
        self.run_task(
            Task(
                {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                payload={"host": "test-apache-with-lfi-and-rce.local", "port": 80},
            )
        )
        (call,) = self.mock_db.save_task_result.call_args_list
        return cast(TaskStatus, call.kwargs["status"])


def shadow_katana() -> None:
    # Models what heavy load did during the 2026-11-18 incident: katana starts but never
    # finishes, so crawling._run_katana_uro kills it after KATANA_TIMEOUT_SECONDS.
    os.makedirs(SHADOW_DIR, exist_ok=True)
    with open(f"{SHADOW_DIR}/katana", "w") as f:
        f.write("#!/bin/sh\nexec sleep 300\n")
    os.chmod(f"{SHADOW_DIR}/katana", 0o755)
    os.environ["PATH"] = f"{SHADOW_DIR}:{os.environ['PATH']}"


def main() -> None:
    healthy = Repro("run_detector").run_detector()
    print(f"healthy katana:   status={healthy}")

    shadow_katana()
    degraded = Repro("run_detector").run_detector()
    print(f"katana shadowed:  status={degraded}")

    if healthy == TaskStatus.INTERESTING and degraded == TaskStatus.OK:
        print(
            "\nBUG reproduced: a genuine LFI+RCE (found when the crawl succeeds) is reported"
            "\nas OK once the katana crawl times out. The only trace is a log WARNING; the"
            "\ntask result looks clean forever instead of erroring or being retried."
        )


if __name__ == "__main__":
    main()
