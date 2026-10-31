from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei_router import (
    NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY,
    NUCLEI_ROUTER_SCAN_MODE_KEY,
    NucleiRouter,
    NucleiScanMode,
)


class NucleiRouterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = NucleiRouter  # type: ignore

    def test_http_service(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-service-with-exposed-apache-config.local", "port": 80},
        )
        self.assertTrue(task.matches_filters(NucleiRouter.filters))

        (routed_task,) = self.run_task(task)
        self.assertEqual(routed_task.headers["type"], TaskType.NUCLEI_TARGET)
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_SCAN_MODE_KEY], NucleiScanMode.HTTP.value)
        # WordPress has not been detected, so WordPress templates should be skipped
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY], ["-etags", "wordpress"])

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["target"], "http://test-service-with-exposed-apache-config.local:80")

    def test_non_http_service(self) -> None:
        # Port scanner reports services without a dedicated Service value (such as Redis) as UNKNOWN
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"host": "test-redis", "port": 6379},
        )
        # Previously the router accepted only HTTP services, so such services were never scanned with Nuclei
        self.assertTrue(task.matches_filters(NucleiRouter.filters))

        (routed_task,) = self.run_task(task)
        self.assertEqual(routed_task.headers["type"], TaskType.NUCLEI_TARGET)
        self.assertEqual(routed_task.payload["host"], "test-redis")
        self.assertEqual(routed_task.payload["port"], 6379)
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_SCAN_MODE_KEY], NucleiScanMode.OTHER.value)
        # Technology detection is HTTP-only, so no additional flags are computed
        self.assertEqual(routed_task.payload[NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY], [])

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["target"], "test-redis:6379")
