#!/usr/bin/env python3
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from karton.core import Task
from karton.core.test import ConfigMock

from artemis.binds import TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.modules.mail_dns_scanner import MailDNSScanner
from artemis.modules.nuclei import Nuclei
from artemis.modules.nuclei_router import NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY


class _MinimalModule(ArtemisBase):
    identity = "minimal-test-module"
    filters = [{"type": TaskType.DOMAIN.value}]


def _domain_task(override: float | None = None) -> Task:
    pp: dict[str, Any] = {"original_domain": "example.com"}
    if override is not None:
        pp["requests_per_second_override"] = override
    return Task(
        {"type": TaskType.DOMAIN},
        payload={"domain": "example.com"},
        payload_persistent=pp,
    )


class TestGetRequestsPerSecondBatchKey(unittest.TestCase):
    module: _MinimalModule

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _MinimalModule(config=ConfigMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def test_no_override_returns_default(self) -> None:
        self.assertEqual(
            str(Config.Limits.REQUESTS_PER_SECOND),
            self.module._get_requests_per_second_batch_key(_domain_task()),
        )

    def test_float_override_returns_string(self) -> None:
        self.assertEqual("2.0", self.module._get_requests_per_second_batch_key(_domain_task(override=2.0)))

    def test_different_overrides_produce_different_keys(self) -> None:
        k1 = self.module._get_requests_per_second_batch_key(_domain_task(override=1.0))
        k2 = self.module._get_requests_per_second_batch_key(_domain_task(override=2.0))
        self.assertNotEqual(k1, k2)

    def test_same_override_produces_same_key(self) -> None:
        k1 = self.module._get_requests_per_second_batch_key(_domain_task(override=1.5))
        k2 = self.module._get_requests_per_second_batch_key(_domain_task(override=1.5))
        self.assertEqual(k1, k2)


class TestBaseBatchGroupKey(unittest.TestCase):
    module: _MinimalModule

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _MinimalModule(config=ConfigMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def test_no_override_returns_default(self) -> None:
        self.assertEqual(
            str(Config.Limits.REQUESTS_PER_SECOND),
            self.module.get_batch_group_key(_domain_task()),
        )

    def test_with_override_returns_non_none(self) -> None:
        self.assertIsNotNone(self.module.get_batch_group_key(_domain_task(override=1.0)))

    def test_same_override_yields_equal_keys(self) -> None:
        self.assertEqual(
            self.module.get_batch_group_key(_domain_task(override=1.0)),
            self.module.get_batch_group_key(_domain_task(override=1.0)),
        )

    def test_different_overrides_yield_different_keys(self) -> None:
        self.assertNotEqual(
            self.module.get_batch_group_key(_domain_task(override=1.0)),
            self.module.get_batch_group_key(_domain_task(override=2.0)),
        )

    def test_no_override_and_with_override_yield_different_keys(self) -> None:
        self.assertNotEqual(
            self.module.get_batch_group_key(_domain_task()),
            self.module.get_batch_group_key(_domain_task(override=1.0)),
        )


class TestNucleiBatchGroupKey(unittest.TestCase):
    module: Nuclei

    @classmethod
    def setUpClass(cls) -> None:
        with patch("artemis.resource_lock.REDIS") as mock_redis:
            mock_redis.set.return_value = True
            cls.module = Nuclei(config=ConfigMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def _task_with_config(
        self,
        router_flags: list[str] | None = None,
        severity_threshold: str | None = None,
        override: float | None = None,
    ) -> Task:
        pp: dict[str, Any] = {"original_domain": "example.com"}
        if severity_threshold is not None:
            pp["module_runtime_configurations"] = {"nuclei-module": {"severity_threshold": severity_threshold}}
        if override is not None:
            pp["requests_per_second_override"] = override
        payload: dict[str, Any] = {"domain": "example.com"}
        if router_flags is not None:
            payload[NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY] = router_flags
        return Task({"type": TaskType.DOMAIN}, payload=payload, payload_persistent=pp)

    def test_same_config_different_override_yields_different_keys(self) -> None:
        self.assertNotEqual(
            self.module.get_batch_group_key(_domain_task()),
            self.module.get_batch_group_key(_domain_task(override=1.0)),
        )

    def test_same_config_same_override_yields_equal_keys(self) -> None:
        self.assertEqual(
            self.module.get_batch_group_key(_domain_task(override=1.0)),
            self.module.get_batch_group_key(_domain_task(override=1.0)),
        )

    def test_router_flags_and_override_are_independent_dimensions(self) -> None:
        task_flags_a = self._task_with_config(router_flags=["--flag-a"], override=1.0)
        task_flags_b = self._task_with_config(router_flags=["--flag-b"], override=1.0)
        self.assertNotEqual(
            self.module.get_batch_group_key(task_flags_a),
            self.module.get_batch_group_key(task_flags_b),
        )

    def test_severity_threshold_and_override_are_independent_dimensions(self) -> None:
        task_high = self._task_with_config(severity_threshold="high_and_above", override=1.0)
        task_medium = self._task_with_config(severity_threshold="medium_and_above", override=1.0)
        self.assertNotEqual(
            self.module.get_batch_group_key(task_high),
            self.module.get_batch_group_key(task_medium),
        )


class TestMailDNSScannerBatchGroupKey(unittest.TestCase):
    module: MailDNSScanner

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = MailDNSScanner(config=ConfigMock(), backend=MagicMock(), db=MagicMock())  # type: ignore[no-untyped-call]

    def _task_with_config(self, report_warnings: bool, override: float | None = None) -> Task:
        pp: dict[str, Any] = {
            "original_domain": "example.com",
            "module_runtime_configurations": {"mail_dns_scanner": {"report_warnings": report_warnings}},
        }
        if override is not None:
            pp["requests_per_second_override"] = override
        return Task({"type": TaskType.DOMAIN}, payload={"domain": "example.com"}, payload_persistent=pp)

    def test_same_config_different_override_yields_different_keys(self) -> None:
        self.assertNotEqual(
            self.module.get_batch_group_key(_domain_task()),
            self.module.get_batch_group_key(_domain_task(override=1.0)),
        )

    def test_same_config_same_override_yields_equal_keys(self) -> None:
        self.assertEqual(
            self.module.get_batch_group_key(_domain_task(override=1.0)),
            self.module.get_batch_group_key(_domain_task(override=1.0)),
        )

    def test_report_warnings_and_override_are_independent_dimensions(self) -> None:
        task_w = self._task_with_config(report_warnings=True, override=1.0)
        task_nw = self._task_with_config(report_warnings=False, override=1.0)
        self.assertNotEqual(
            self.module.get_batch_group_key(task_w),
            self.module.get_batch_group_key(task_nw),
        )


if __name__ == "__main__":
    unittest.main()
