import re
import urllib.parse
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei
from artemis.modules.nuclei_router import NUCLEI_ROUTER_SCAN_MODE_KEY, NucleiScanMode


def _param_names(url: str) -> list[str]:
    return list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True).keys())


def _reflected_xss_urls(status_reason: str) -> list[str]:
    """The PoC URLs reported for the reflected XSS DAST template."""
    return re.findall(r"\[medium\]\s+(\S+): Reflected Cross-Site Scripting", status_reason)


class NucleiTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def test_dast_template(self) -> None:
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-dast-vuln-app.local",
                "port": 5000,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn(
            "Local File Inclusion Directory traversal vulnerability in the Helpdesk Pro plugin before 1.4.0 for Joomla! allows remote attackers to read arbitrary files via a .. ",
            call.kwargs["status_reason"],
        )
        self.assertIn(
            "Local File Inclusion - Linux",
            call.kwargs["status_reason"],
        )
        self.assertIn(
            "LFI Detection - Keyed",
            call.kwargs["status_reason"],
        )
        self.assertIn(
            "Reflected SSTI Arithmetic Based",
            call.kwargs["status_reason"],
        )


class NucleiShortTemplateListTest(ArtemisModuleTestCase):
    # Tests with template list shortened to speed up test runtime

    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def setUp(self) -> None:
        # list of templates used in tests
        self.patcher = patch(
            "artemis.config.Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN",
            [
                "http/cves/2020/CVE-2020-28976.yaml",
                "http/vulnerabilities/generic/top-xss-params.yaml",
                "http/vulnerabilities/generic/xss-fuzz.yaml",
                "dast/vulnerabilities/xss/reflected-xss.yaml",
                "http/exposures/configs/apache-config.yaml",
            ],
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

        return super().setUp()

    def test_severity_threshold(self) -> None:
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-service-with-exposed-apache-config.local",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei-module": {"severity_threshold": "critical_only"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        # Should find nothing if the severity threshold is set to critical, as the template is not critical-severity
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

        self.mock_db.reset_mock()

        # Using previous identity for backwardcompatibilty testing during migration
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-service-with-exposed-apache-config.local",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei": {"severity_threshold": "medium_and_above"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

    def test_403_bypass_workflow(self) -> None:
        # workflows use additional list of templates
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-php-403-bypass.local",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "[medium] http://test-php-403-bypass.local:80: 403 Forbidden Bypass Detection with Headers Detects potential 403 Forbidden bypass vulnerabilities by adding headers (e.g., X-Forwarded-For, X-Original-URL).\n",
        )

    def test_interactsh(self) -> None:
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-php-mock-CVE-2020-28976.local",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei-module": {"severity_threshold": "medium_and_above"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertRegex(
            call.kwargs["status_reason"],
            r"\[medium\] http://test-php-mock-CVE-2020-28976\.local:80/wp-content/plugins/canto/includes/lib/get\.php\?subdomain=[a-z0-9\.]+: WordPress Canto 1\.3\.0 - Blind Server-Side Request Forgery WordPress Canto plugin 1\.3\.0 is susceptible to blind server-side request forgery\. An attacker can make a request to any internal and external server via /includes/lib/detail\.php\?subdomain and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site\.",
        )

    def test_poc_url_shortened_when_one_param_is_enough(self) -> None:
        """/xss.php reflects `search` on its own, so the PoC URL - built from
        the whole DAST wordlist - is shortened to that single parameter."""
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-php-xss-but-not-on-homepage.local",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        urls = _reflected_xss_urls(call.kwargs["status_reason"])
        self.assertTrue(urls)
        for url in urls:
            self.assertEqual(_param_names(url), ["search"])

    def test_poc_url_kept_whole_when_the_finding_needs_a_second_param(self) -> None:
        """The app reflects `search` only if `login` is present. Nuclei's
        single-mode re-fuzz reports `search` alone, because it keeps sending
        `login` alongside it - so shortening the PoC to `?search=...` would
        produce a URL that no longer reproduces the vulnerability. Artemis
        must notice that and report the full URL instead."""
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-php-xss-requiring-second-param.local",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        urls = _reflected_xss_urls(call.kwargs["status_reason"])
        self.assertTrue(urls)
        for url in urls:
            param_names = _param_names(url)
            self.assertIn("search", param_names)
            self.assertIn("login", param_names)

    def test_links(self) -> None:
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-php-xss-but-not-on-homepage.local",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertRegex(
            call.kwargs["status_reason"],
            r"(?s)\[high\]\s+http://test-php-xss-but-not-on-homepage\.local/xss\.php/\?.*?"
            r"Top 38 Parameters - Cross-Site Scripting",
        )
        self.assertRegex(
            call.kwargs["status_reason"],
            r"(?s)\[medium\]\s+http://test-php-xss-but-not-on-homepage\.local/xss\.php/\?.*?"
            r"Fuzzing Parameters - Cross-Site Scripting",
        )
        self.assertRegex(
            call.kwargs["status_reason"],
            r"(?s)\[medium\]\s+http://test-php-xss-but-not-on-homepage\.local/xss\.php\?.*?"
            r"Reflected Cross-Site Scripting",
        )


class NucleiNonHttpServiceTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def setUp(self) -> None:
        # An HTTP template is included to check that HTTP templates are not run on non-HTTP services
        self.patcher = patch(
            "artemis.config.Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN",
            [
                "network/exposures/exposed-redis.yaml",
                "http/exposures/configs/apache-config.yaml",
            ],
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

        return super().setUp()

    def test_unauthenticated_redis(self) -> None:
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-redis",
                "port": 6379,
                NUCLEI_ROUTER_SCAN_MODE_KEY: NucleiScanMode.OTHER.value,
            },
        )
        with (
            patch.object(self.karton, "_get_links") as get_links,
            patch.object(self.karton, "_scan", wraps=self.karton._scan) as scan,
        ):
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("[high] test-redis:6379: Redis Server - Unauthenticated Access", call.kwargs["status_reason"])

        # Only the templates are run, on host:port - no workflows, DAST or link crawling, as they are HTTP-only
        (scan_call,) = scan.call_args_list
        self.assertEqual(scan_call.args[2], ["test-redis:6379"])
        self.assertIn("-ept", scan_call.kwargs["extra_nuclei_args"])
        get_links.assert_not_called()

    def test_unauthenticated_redis_on_non_standard_port(self) -> None:
        # The template lists ports 6379 and 6380 - the port of the scanned service should be used instead
        task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-redis-non-standard-port",
                "port": 7000,
                NUCLEI_ROUTER_SCAN_MODE_KEY: NucleiScanMode.OTHER.value,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn(
            "[high] test-redis-non-standard-port:7000: Redis Server - Unauthenticated Access",
            call.kwargs["status_reason"],
        )

    def test_redis_on_host_with_http_is_found_only_by_non_http_scan(self) -> None:
        # TCP (network) templates run as a part of an HTTP scan connect only to the HTTP port, so they don't
        # detect Redis running on the same host - it needs to be scanned as a separate service.
        http_task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={"host": "test-redis-with-http", "port": 80},
        )
        self.run_task(http_task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

        self.mock_db.reset_mock()

        redis_task = Task(
            {"type": TaskType.NUCLEI_TARGET},
            payload={
                "host": "test-redis-with-http",
                "port": 6379,
                NUCLEI_ROUTER_SCAN_MODE_KEY: NucleiScanMode.OTHER.value,
            },
        )
        self.run_task(redis_task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn(
            "[high] test-redis-with-http:6379: Redis Server - Unauthenticated Access", call.kwargs["status_reason"]
        )
