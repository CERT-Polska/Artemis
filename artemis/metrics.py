import time
from typing import Generator

from karton.core.backend import KartonBackend, KartonMetrics
from karton.core.config import Config as KartonConfig
from prometheus_client import (
    GC_COLLECTOR,
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    REGISTRY,
    start_http_server,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector


class ArtemisMetricsCollector(Collector):
    def collect(self) -> Generator[GaugeMetricFamily, None, None]:
        # We check the backend redis queue length directly to avoid the long runtimes of
        # KartonState.get_all_tasks()
        backend = KartonBackend(config=KartonConfig())

        yield GaugeMetricFamily(
            "tasks_consumed",
            "Karton tasks consumed",
            value=sum(map(int, backend.redis.hvals(KartonMetrics.TASK_CONSUMED.value))),
        )
        yield GaugeMetricFamily(
            "tasks_crashed",
            "Karton tasks crashed",
            value=sum(map(int, backend.redis.hvals(KartonMetrics.TASK_CRASHED.value))),
        )
        yield GaugeMetricFamily(
            "tasks_queued",
            "Karton tasks queued",
            value=sum([backend.redis.llen(key) for key in backend.redis.keys("karton.queue.*")]),
        )

        # We count the number of tasks for these kartons separately as each task pending on them tends to produce
        # a large number of tasks for other kartons - so we want to monitor the queue length separately.
        high_level_kartons = ["port_scanner", "subdomain_enumeration"]

        num_tasks_high_level_kartons = 0
        for karton_name in high_level_kartons:
            num_tasks_high_level_kartons += sum(
                [backend.redis.llen(key) for key in backend.redis.keys(f"karton.queue.*:{karton_name}")]
            )

        yield GaugeMetricFamily(
            "tasks_queued_high_level_kartons",
            "Karton tasks queued for high level kartons (e.g. port scanning or subdomain enumeration) that tend to spawn a "
            "large number of other tasks.",
            value=num_tasks_high_level_kartons,
        )


if __name__ == "__main__":
    start_http_server(9000)
    REGISTRY.register(ArtemisMetricsCollector())
    REGISTRY.unregister(GC_COLLECTOR)
    REGISTRY.unregister(PLATFORM_COLLECTOR)
    REGISTRY.unregister(PROCESS_COLLECTOR)

    while True:
        time.sleep(1)
