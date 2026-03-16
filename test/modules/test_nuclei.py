from test.base import ArtemisModuleTestCase
from unittest import skip
from unittest.mock import patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei


class NucleiTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def test_severity_threshold(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-service-with-exposed-apache-config",
                "port": 80,
            },
            payload_persistent={"module_runtime_configurations": {"nuclei": {"severity_threshold": "critical_only"}}},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        # Should find nothing if the severity threshold is set to critical, as the template is not critical-severity
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

        self.mock_db.reset_mock()

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-service-with-exposed-apache-config",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei": {"severity_threshold": "medium_and_above"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

    def test_dast_template(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-dast-vuln-app",
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
            ],
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

        return super().setUp()

    def test_403_bypass_workflow(self) -> None:
        # workflows use additional list of templates
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-403-bypass",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "[medium] http://test-php-403-bypass:80: 403 Forbidden Bypass Detection with Headers Detects potential 403 Forbidden bypass vulnerabilities by adding headers (e.g., X-Forwarded-For, X-Original-URL).\n",
        )

    @skip("Reason: failing on GH CI")
    def test_interactsh(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-mock-CVE-2020-28976",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei": {"severity_threshold": "medium_and_above"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertRegex(
            call.kwargs["status_reason"],
            r"\[medium\] http://test-php-mock-CVE-2020-28976:80/wp-content/plugins/canto/includes/lib/get\.php\?subdomain=[a-z0-9\.]+: WordPress Canto 1\.3\.0 - Blind Server-Side Request Forgery WordPress Canto plugin 1\.3\.0 is susceptible to blind server-side request forgery\. An attacker can make a request to any internal and external server via /includes/lib/detail\.php\?subdomain and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site\.",
        )

    def test_links(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-xss-but-not-on-homepage",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertRegex(
            call.kwargs["status_reason"],
            r"(?s)\[high\]\s+http://test-php-xss-but-not-on-homepage:80/xss\.php/\?.*?"
            r"Top 38 Parameters - Cross-Site Scripting",
        )
        self.assertRegex(
            call.kwargs["status_reason"],
            r"(?s)\[medium\]\s+http://test-php-xss-but-not-on-homepage:80/xss\.php/\?.*?"
            r"Fuzzing Parameters - Cross-Site Scripting",
        )
        self.assertRegex(
            call.kwargs["status_reason"],
            r"(?s)\[medium\]\s+http://test-php-xss-but-not-on-homepage:80/xss\.php\?.*?"
            r"Reflected Cross-Site Scripting",
        )
