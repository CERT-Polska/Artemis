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
            r"^\[high\] http://test-php-xss-but-not-on-homepage:80/xss\.php/\?q=%27%3E%22%3Csvg%2Fonload=confirm%28%27q%27%29%3E&s=%27%3E%22%3Csvg%2Fonload=confirm%28%27s%27%29%3E&search=%27%3E%22%3Csvg%2Fonload=confirm%28%27search%27%29%3E&id=%27%3E%22%3Csvg%2Fonload=confirm%28%27id%27%29%3E&action=%27%3E%22%3Csvg%2Fonload=confirm%28%27action%27%29%3E&keyword=%27%3E%22%3Csvg%2Fonload=confirm%28%27keyword%27%29%3E&query=%27%3E%22%3Csvg%2Fonload=confirm%28%27query%27%29%3E&page=%27%3E%22%3Csvg%2Fonload=confirm%28%27page%27%29%3E&keywords=%27%3E%22%3Csvg%2Fonload=confirm%28%27keywords%27%29%3E&url=%27%3E%22%3Csvg%2Fonload=confirm%28%27url%27%29%3E&view=%27%3E%22%3Csvg%2Fonload=confirm%28%27view%27%29%3E&cat=%27%3E%22%3Csvg%2Fonload=confirm%28%27cat%27%29%3E&name=%27%3E%22%3Csvg%2Fonload=confirm%28%27name%27%29%3E&key=%27%3E%22%3Csvg%2Fonload=confirm%28%27key%27%29%3E&p=%27%3E%22%3Csvg%2Fonload=confirm%28%27p%27%29%3E: Top 38 Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests\., "
            r"\[medium\] http://test-php-xss-but-not-on-homepage:80/xss\.php/\?deleted=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-deleted%27%29%3E&search=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-search%27%29%3E&action=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-action%27%29%3E&newname=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-newname%27%29%3E&info=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-info%27%29%3E&content=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-content%27%29%3E&signature=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-signature%27%29%3E&noconfirmation=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-noconfirmation%27%29%3E&field=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-field%27%29%3E&output=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-output%27%29%3E&city=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-city%27%29%3E&rename=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-rename%27%29%3E&mail=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-mail%27%29%3E&term=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-term%27%29%3E: Fuzzing Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests\.\n, "
            r"\[medium\] http://test-php-xss-but-not-on-homepage:80/xss\.php\?.*\'\"><\d+>.*: Reflected Cross-Site Scripting $",
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
        self.assertRegex(
            call.kwargs["status_reason"],
            r"\[high\] http://test-dast-vuln-app:5000/\?option=com_helpdeskpro&task=ticket.download_attachment&filename=/../../../../../../../../../../../../etc/passwd&original_filename=AnyFileName.exe: Joomla! Helpdesk Pro plugin <1.4.0 - Local File Inclusion Directory traversal vulnerability in the Helpdesk Pro plugin before 1.4.0 for Joomla! allows remote attackers to read arbitrary files via a .. \(dot dot\) in the filename parameter in a ticket.download_attachment task., "
            r"\[high\] http://test-dast-vuln-app:5000\?dest=/etc/passwd&redirect=/etc/passwd&uri=/etc/passwd&path=/etc/passwd&continue=/etc/passwd&url=/etc/passwd&window=/etc/passwd&next=/etc/passwd&data=/etc/passwd&reference=/etc/passwd&site=/etc/passwd&html=/etc/passwd&val=/etc/passwd&validate=/etc/passwd&domain=/etc/passwd&callback=/etc/passwd&return=/etc/passwd&page=/etc/passwd&feed=/etc/passwd&host=/etc/passwd&port=/etc/passwd&to=/etc/passwd&out=/etc/passwd&view=/etc/passwd&dir=/etc/passwd&target=/etc/passwd&rurl=/etc/passwd&destination=/etc/passwd&redir=/etc/passwd&redirect_uri=/etc/passwd&image_url=/etc/passwd&go=/etc/passwd&returnTo=/etc/passwd&return_to=/etc/passwd&checkout_url=/etc/passwd&return_path=/etc/passwd&cat=/etc/passwd&action=/etc/passwd&board=/etc/passwd&date=/etc/passwd&detail=/etc/passwd&file=/etc/passwd&filename=/etc/passwd&download=/etc/passwd&folder=/etc/passwd&prefix=/etc/passwd&include=/etc/passwd&inc=/etc/passwd&locate=/etc/passwd&show=/etc/passwd&doc=/etc/passwd&type=/etc/passwd&content=/etc/passwd&document=/etc/passwd&layout=/etc/passwd&mod=/etc/passwd&conf=/etc/passwd&cmd=/etc/passwd&exec=/etc/passwd&command=/etc/passwd&execute=/etc/passwd&ping=/etc/passwd&query=/etc/passwd&jump=/etc/passwd&code=/etc/passwd&reg=/etc/passwd&do=/etc/passwd&func=/etc/passwd&arg=/etc/passwd&option=/etc/passwd&load=/etc/passwd&process=/etc/passwd&step=/etc/passwd&read=/etc/passwd&function=/etc/passwd&req=/etc/passwd&feature=/etc/passwd&exe=/etc/passwd&module=/etc/passwd&payload=/etc/passwd&run=/etc/passwd&print=/etc/passwd&id=/etc/passwd&search=/etc/passwd&category=/etc/passwd&class=/etc/passwd&news=/etc/passwd&item=/etc/passwd&menu=/etc/passwd&lang=/etc/passwd&name=/etc/passwd&ref=/etc/passwd&title=/etc/passwd&topic=/etc/passwd&thread=/etc/passwd&form=/etc/passwd&join=/etc/passwd&main=/etc/passwd&nav=/etc/passwd&region=/etc/passwd&q=/etc/passwd&s=/etc/passwd&keyword=/etc/passwd&keywords=/etc/passwd&year=/etc/passwd&email=/etc/passwd&p=/etc/passwd&month=/etc/passwd&image=/etc/passwd&list_type=/etc/passwd&terms=/etc/passwd&categoryid=/etc/passwd&key=/etc/passwd&login=/etc/passwd&begindate=/etc/passwd&enddate=/etc/passwd: Local File Inclusion - Linux , "
            r"\[high\] http://test-dast-vuln-app:5000\?dest=http%3A%2F%2F127.0.0.1%2Fabc.html&redirect=http%3A%2F%2F127.0.0.1%2Fabc.html&uri=http%3A%2F%2F127.0.0.1%2Fabc.html&path=http%3A%2F%2F127.0.0.1%2Fabc.html&continue=http%3A%2F%2F127.0.0.1%2Fabc.html&url=http%3A%2F%2F127.0.0.1%2Fabc.html&window=http%3A%2F%2F127.0.0.1%2Fabc.html&next=http%3A%2F%2F127.0.0.1%2Fabc.html&data=http%3A%2F%2F127.0.0.1%2Fabc.html&reference=http%3A%2F%2F127.0.0.1%2Fabc.html&site=http%3A%2F%2F127.0.0.1%2Fabc.html&html=http%3A%2F%2F127.0.0.1%2Fabc.html&val=http%3A%2F%2F127.0.0.1%2Fabc.html&validate=http%3A%2F%2F127.0.0.1%2Fabc.html&domain=http%3A%2F%2F127.0.0.1%2Fabc.html&callback=http%3A%2F%2F127.0.0.1%2Fabc.html&return=http%3A%2F%2F127.0.0.1%2Fabc.html&page=http%3A%2F%2F127.0.0.1%2Fabc.html&feed=http%3A%2F%2F127.0.0.1%2Fabc.html&host=http%3A%2F%2F127.0.0.1%2Fabc.html&port=http%3A%2F%2F127.0.0.1%2Fabc.html&to=http%3A%2F%2F127.0.0.1%2Fabc.html&out=http%3A%2F%2F127.0.0.1%2Fabc.html&view=http%3A%2F%2F127.0.0.1%2Fabc.html&dir=http%3A%2F%2F127.0.0.1%2Fabc.html&target=http%3A%2F%2F127.0.0.1%2Fabc.html&rurl=http%3A%2F%2F127.0.0.1%2Fabc.html&destination=http%3A%2F%2F127.0.0.1%2Fabc.html&redir=http%3A%2F%2F127.0.0.1%2Fabc.html&redirect_uri=http%3A%2F%2F127.0.0.1%2Fabc.html&image_url=http%3A%2F%2F127.0.0.1%2Fabc.html&go=http%3A%2F%2F127.0.0.1%2Fabc.html&returnTo=http%3A%2F%2F127.0.0.1%2Fabc.html&return_to=http%3A%2F%2F127.0.0.1%2Fabc.html&checkout_url=http%3A%2F%2F127.0.0.1%2Fabc.html&return_path=http%3A%2F%2F127.0.0.1%2Fabc.html&cat=abc.html&action=abc.html&board=abc.html&date=abc.html&detail=abc.html&file=abc.html&filename=../../../../../../../../../../../../../../../etc/passwd&download=abc.html&folder=abc.html&prefix=abc.html&include=abc.html&inc=abc.html&locate=abc.html&show=abc.html&doc=abc.html&type=abc.html&content=abc.html&document=abc.html&layout=abc.html&mod=abc.html&conf=abc.html&cmd=testing&exec=testing&command=testing&execute=testing&ping=testing&query=testing&jump=testing&code=testing&reg=testing&do=testing&func=testing&arg=testing&option=testing&load=testing&process=testing&step=testing&read=testing&function=testing&req=testing&feature=testing&exe=testing&module=testing&payload=testing&run=testing&print=testing&id=testing&search=testing&category=testing&class=testing&news=testing&item=testing&menu=testing&lang=testing&name=testing&ref=testing&title=testing&topic=testing&thread=testing&form=testing&join=testing&main=testing&nav=testing&region=testing&q=testing&s=testing&keyword=testing&keywords=testing&year=testing&email=testing&p=testing&month=testing&image=testing&list_type=testing&terms=testing&categoryid=testing&key=testing&login=testing&begindate=testing&enddate=testing: LFI Detection - Keyed , "
            r"\[medium\] http://test-dast-vuln-app:5000/ssti\?[a-zA-Z_]+=[^&]*\{\{\d+\*\d+\}\}(?:&[a-zA-Z_]+=[^&]*\{\{\d+\*\d+\}\})*: Reflected SSTI Arithmetic Based $",
        )
