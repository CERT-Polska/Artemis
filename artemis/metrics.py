import time
from datetime import datetime, timedelta, timezone
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
from redis import Redis

from artemis.config import Config
from artemis.db import DB
from artemis.task_utils import (
    ARTEMIS_INTERESTING_TASKS_KEY_PREFIX,
    INTERESTING_TASKS_REDIS_TTL_SECONDS,
)
from artemis.utils import build_logger

db = DB()
artemis_redis = Redis.from_url(Config.Data.REDIS_CONN_STR)
LOGGER = build_logger(__name__)
SYNC_POSTGRES_REDIS_INTERVAL_SECONDS = 3600


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
        for key in self.backend.redis.scan_iter("karton.queue.*"):
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

        interesting = GaugeMetricFamily(
            "tasks_interesting_status",
            "Karton tasks with interesting findings",
            labels=["date", "karton"],
        )
        today_str = datetime.now(timezone.utc).date().isoformat()
        interesting_today = GaugeMetricFamily(
            "tasks_interesting_today",
            "Karton tasks with interesting findings for the current day",
            labels=["karton"],
        )
        for key in artemis_redis.scan_iter(f"{ARTEMIS_INTERESTING_TASKS_KEY_PREFIX}*"):
            key_str = key.decode() if isinstance(key, bytes) else key
            day = key_str[len(ARTEMIS_INTERESTING_TASKS_KEY_PREFIX) :]
            for field, count in artemis_redis.hgetall(key).items():
                receiver = field.decode() if isinstance(field, bytes) else field
                interesting.add_metric([day, receiver], int(count))
                if day == today_str:
                    interesting_today.add_metric([receiver], int(count))
        yield interesting
        yield interesting_today


def sync_interesting_findings() -> None:
    today = datetime.now(timezone.utc).date()
    for day in (today, today - timedelta(days=1)):
        counts = db.count_interesting_tasks_by_receiver(day)
        key = ARTEMIS_INTERESTING_TASKS_KEY_PREFIX + day.isoformat()
        pipe = artemis_redis.pipeline()
        pipe.delete(key)
        if counts:
            pipe.hset(key, mapping=counts)  # type: ignore[arg-type]
        pipe.expire(key, INTERESTING_TASKS_REDIS_TTL_SECONDS)
        pipe.execute()
    LOGGER.info("Synced interesting task counts for today and yesterday")


if __name__ == "__main__":
    start_http_server(9000)
    REGISTRY.register(ArtemisMetricsCollector())
    REGISTRY.unregister(GC_COLLECTOR)
    REGISTRY.unregister(PLATFORM_COLLECTOR)
    REGISTRY.unregister(PROCESS_COLLECTOR)

    last_sync_at = 0.0
    while True:
        time.sleep(1)
        if time.time() - last_sync_at > SYNC_POSTGRES_REDIS_INTERVAL_SECONDS:
            try:
                sync_interesting_findings()
                last_sync_at = time.time()
            except Exception:
                LOGGER.exception("Error during sync of interesting task counts")
