import logging
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei, group_targets_by_missing_tech


class NucleiTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def test_403_bypass_workflow(self) -> None:
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
        self.assertEqual(
            call.kwargs["status_reason"],
            "[medium] http://test-php-mock-CVE-2020-28976:80: WordPress Canto 1.3.0 - Blind Server-Side Request Forgery WordPress Canto plugin 1.3.0 is susceptible to blind server-side request forgery. An attacker can make a request to any internal and external server via /includes/lib/detail.php?subdomain and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.",
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
        self.assertEqual(
            call.kwargs["status_reason"],
            "[high] http://test-php-xss-but-not-on-homepage:80/xss.php: Top 38 Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter "
            "values in the server response via GET-requests., [medium] http://test-php-xss-but-not-on-homepage:80/xss.php: Fuzzing Parameters - Cross-Site Scripting Cross-site scripting "
            "was discovered via a search for reflected parameter values in the server response via GET-requests.\n, "
            "[medium] http://test-php-xss-but-not-on-homepage:80/xss.php?q=testing&s=testing&search=testing&id=testing&lang=testing&keyword=testing&query=testing&page=testing&keywords=testing&year=testing&view=testing&email=testing&type=testing&name=testing&p=testing&month=testing&image=testing&list_type=testing&url=testing&terms=testing&categoryid=testing&key=testing&login=testing&begindate=testing&enddate=testing: Reflected Cross-Site Scripting ",
        )

    def test_group_targets_by_missing_tech(self) -> None:
        targets = [
            "http://test-old-wordpress",
            "http://test-old-joomla",
            "http://test-flask-vulnerable-api:5000",
        ]
        logger = logging.Logger("test_logger")

        grouped_targets = group_targets_by_missing_tech(targets, logger)

        expected_results = {
            frozenset(["wordpress"]): [targets[1], targets[2]],
        }

        self.assertIn(frozenset(["wordpress"]), grouped_targets)
        self.assertEqual(grouped_targets[frozenset(["wordpress"])], expected_results[frozenset(["wordpress"])])

    def test_lfi_dast_template(self) -> None:
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
        self.assertEqual(
            call.kwargs["status_reason"],
            "[high] http://test-dast-vuln-app:5000: Joomla! Helpdesk Pro plugin <1.4.0 - Local File Inclusion Directory traversal vulnerability in the Helpdesk Pro plugin before 1.4.0 for Joomla! allows remote attackers to read arbitrary files via a .. (dot dot) in the filename parameter in a ticket.download_attachment task., "
            "[high] http://test-dast-vuln-app:5000?cat=abc.html&dir=abc.html&action=abc.html&board=abc.html&date=abc.html&detail=abc.html&file=abc.html&filename=abc.html&download=abc.html&path=abc.html&folder=abc.html&prefix=abc.html&include=abc.html&page=abc.html&inc=abc.html&locate=abc.html&show=abc.html&doc=abc.html&site=abc.html&type=abc.html&view=abc.html&content=abc.html&document=abc.html&layout=abc.html&mod=abc.html&conf=abc.html: LFI Detection - Keyed , "
            "[high] http://test-dast-vuln-app:5000?cat=abc.html&dir=abc.html&action=abc.html&board=abc.html&date=abc.html&detail=abc.html&file=abc.html&filename=abc.html&download=abc.html&path=abc.html&folder=abc.html&prefix=abc.html&include=abc.html&page=abc.html&inc=abc.html&locate=abc.html&show=abc.html&doc=abc.html&site=abc.html&type=abc.html&view=abc.html&content=abc.html&document=abc.html&layout=abc.html&mod=abc.html&conf=abc.html: Local File Inclusion - Linux , "
            "[medium] http://test-dast-vuln-app:5000/ssti?template=Testing&cat=abc.html&dir=abc.html&action=abc.html&board=abc.html&date=abc.html&detail=abc.html&file=abc.html&filename=abc.html&download=abc.html&path=abc.html&folder=abc.html&prefix=abc.html&include=abc.html&page=abc.html&inc=abc.html&locate=abc.html&show=abc.html&doc=abc.html&site=abc.html&type=abc.html&view=abc.html&content=abc.html&document=abc.html&layout=abc.html&mod=abc.html&conf=abc.html: Reflected SSTI Arithmetic Based , "
            "[medium] http://test-dast-vuln-app:5000/ssti?template=Testing&cmd=testing&exec=testing&command=testing&execute=testing&ping=testing&query=testing&jump=testing&code=testing&reg=testing&do=testing&func=testing&arg=testing&option=testing&load=testing&process=testing&step=testing&read=testing&function=testing&req=testing&feature=testing&exe=testing&module=testing&payload=testing&run=testing&print=testing: Reflected SSTI Arithmetic Based , "
            "[medium] http://test-dast-vuln-app:5000/ssti?template=Testing&dest=http%3A%2F%2F127.0.0.1&redirect=http%3A%2F%2F127.0.0.1&uri=http%3A%2F%2F127.0.0.1&path=http%3A%2F%2F127.0.0.1&continue=http%3A%2F%2F127.0.0.1&url=http%3A%2F%2F127.0.0.1&window=http%3A%2F%2F127.0.0.1&next=http%3A%2F%2F127.0.0.1&data=http%3A%2F%2F127.0.0.1&reference=http%3A%2F%2F127.0.0.1&site=http%3A%2F%2F127.0.0.1&html=http%3A%2F%2F127.0.0.1&val=http%3A%2F%2F127.0.0.1&validate=http%3A%2F%2F127.0.0.1&domain=http%3A%2F%2F127.0.0.1&callback=http%3A%2F%2F127.0.0.1&return=http%3A%2F%2F127.0.0.1&page=http%3A%2F%2F127.0.0.1&feed=http%3A%2F%2F127.0.0.1&host=http%3A%2F%2F127.0.0.1&port=http%3A%2F%2F127.0.0.1&to=http%3A%2F%2F127.0.0.1&out=http%3A%2F%2F127.0.0.1&view=http%3A%2F%2F127.0.0.1&dir=http%3A%2F%2F127.0.0.1: Reflected SSTI Arithmetic Based , "
            "[medium] http://test-dast-vuln-app:5000/ssti?template=Testing&id=testing&page=testing&dir=testing&search=testing&category=testing&file=testing&class=testing&url=testing&news=testing&item=testing&menu=testing&lang=testing&name=testing&ref=testing&title=testing&view=testing&topic=testing&thread=testing&type=testing&date=testing&form=testing&join=testing&main=testing&nav=testing&region=testing: Reflected SSTI Arithmetic Based , "
            "[medium] http://test-dast-vuln-app:5000/ssti?template=Testing&next=http%3A%2F%2F127.0.0.1&url=http%3A%2F%2F127.0.0.1&target=http%3A%2F%2F127.0.0.1&rurl=http%3A%2F%2F127.0.0.1&dest=http%3A%2F%2F127.0.0.1&destination=http%3A%2F%2F127.0.0.1&redir=http%3A%2F%2F127.0.0.1&redirect_uri=http%3A%2F%2F127.0.0.1&redirect=http%3A%2F%2F127.0.0.1&out=http%3A%2F%2F127.0.0.1&view=http%3A%2F%2F127.0.0.1&to=http%3A%2F%2F127.0.0.1&image_url=http%3A%2F%2F127.0.0.1&go=http%3A%2F%2F127.0.0.1&return=http%3A%2F%2F127.0.0.1&returnTo=http%3A%2F%2F127.0.0.1&return_to=http%3A%2F%2F127.0.0.1&checkout_url=http%3A%2F%2F127.0.0.1&continue=http%3A%2F%2F127.0.0.1&return_path=http%3A%2F%2F127.0.0.1: Reflected SSTI Arithmetic Based , [medium] http://test-dast-vuln-app:5000/ssti?template=Testing&q=testing&s=testing&search=testing&id=testing&lang=testing&keyword=testing&query=testing&page=testing&keywords=testing&year=testing&view=testing&email=testing&type=testing&name=testing&p=testing&month=testing&image=testing&list_type=testing&url=testing&terms=testing&categoryid=testing&key=testing&login=testing&begindate=testing&enddate=testing: Reflected Cross-Site Scripting , [medium] http://test-dast-vuln-app:5000/ssti?template=Testing&q=testing&s=testing&search=testing&id=testing&lang=testing&keyword=testing&query=testing&page=testing&keywords=testing&year=testing&view=testing&email=testing&type=testing&name=testing&p=testing&month=testing&image=testing&list_type=testing&url=testing&terms=testing&categoryid=testing&key=testing&login=testing&begindate=testing&enddate=testing: Reflected SSTI Arithmetic Based ",
        )
