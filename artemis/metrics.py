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

from artemis.task_utils import ARTEMIS_INTERESTING_TASKS_NUMBER_KEY


class ArtemisMetricsCollector(Collector):
    def __init__(self) -> None:
        # We check the backend redis queue length directly to avoid the long runtimes of
        # KartonState.get_all_tasks()
        self.backend = KartonBackend(config=KartonConfig())

    def collect(self) -> Generator[GaugeMetricFamily, None, None]:
        yield GaugeMetricFamily(
            "tasks_consumed",
            "Karton tasks consumed",
            value=sum(map(int, self.backend.redis.hvals(KartonMetrics.TASK_CONSUMED.value))),
        )
        yield GaugeMetricFamily(
            "tasks_crashed",
            "Karton tasks crashed",
            value=sum(map(int, self.backend.redis.hvals(KartonMetrics.TASK_CRASHED.value))),
        )
        queue_lengths: dict[str, int] = {}
        for key in self.backend.redis.keys("karton.queue.*"):
            karton_name = key.split(":")[-1]
            queue_lengths[karton_name] = queue_lengths.get(karton_name, 0) + self.backend.redis.llen(key)

        yield GaugeMetricFamily(
            "tasks_queued",
            "Karton tasks queued",
            value=sum(queue_lengths.values()),
        )

        queue_length_per_karton = GaugeMetricFamily(
            "tasks_queued_per_karton",
            "Karton tasks queued per karton queue",
            labels=["karton"],
        )
        for karton_name, length in queue_lengths.items():
            queue_length_per_karton.add_metric([karton_name], length)
        yield queue_length_per_karton

        # We count the number of tasks for these kartons separately as each task pending on them tends to produce
        # a large number of tasks for other kartons - so we want to monitor the queue length separately.
        high_level_kartons = ["port_scanner", "subdomain_enumeration"]

        num_tasks_high_level_kartons = sum(queue_lengths.get(karton_name, 0) for karton_name in high_level_kartons)

        yield GaugeMetricFamily(
            "tasks_queued_high_level_kartons",
            "Karton tasks queued for high level kartons (e.g. port scanning or subdomain enumeration) that tend to spawn a "
            "large number of other tasks.",
            value=num_tasks_high_level_kartons,
        )

        interesting = {
            (k.decode() if isinstance(k, bytes) else k): int(v)
            for k, v in self.backend.redis.hgetall(ARTEMIS_INTERESTING_TASKS_NUMBER_KEY).items()
        }

        yield GaugeMetricFamily(
            "tasks_interesting",
            "Karton tasks with interesting findings",
            value=sum(interesting.values()),
        )

        interesting_per_karton = GaugeMetricFamily(
            "tasks_interesting_per_karton",
            "Karton tasks with interesting findings per karton",
            labels=["karton"],
        )

        for karton_name, count in interesting.items():
            interesting_per_karton.add_metric([karton_name], count)

        yield interesting_per_karton


if __name__ == "__main__":
    start_http_server(9000)
    REGISTRY.register(ArtemisMetricsCollector())
    REGISTRY.unregister(GC_COLLECTOR)
    REGISTRY.unregister(PLATFORM_COLLECTOR)
    REGISTRY.unregister(PROCESS_COLLECTOR)

    while True:
        time.sleep(1)
