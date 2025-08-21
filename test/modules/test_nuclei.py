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
        self.assertRegex(
            call.kwargs["status_reason"],
            r"^\[high\] http://test-php-xss-but-not-on-homepage:80/xss\.php/\?q=%27%3E%22%3Csvg%2Fonload=confirm%28%27q%27%29%3E&s=%27%3E%22%3Csvg%2Fonload=confirm%28%27s%27%29%3E&search=%27%3E%22%3Csvg%2Fonload=confirm%28%27search%27%29%3E&id=%27%3E%22%3Csvg%2Fonload=confirm%28%27id%27%29%3E&action=%27%3E%22%3Csvg%2Fonload=confirm%28%27action%27%29%3E&keyword=%27%3E%22%3Csvg%2Fonload=confirm%28%27keyword%27%29%3E&query=%27%3E%22%3Csvg%2Fonload=confirm%28%27query%27%29%3E&page=%27%3E%22%3Csvg%2Fonload=confirm%28%27page%27%29%3E&keywords=%27%3E%22%3Csvg%2Fonload=confirm%28%27keywords%27%29%3E&url=%27%3E%22%3Csvg%2Fonload=confirm%28%27url%27%29%3E&view=%27%3E%22%3Csvg%2Fonload=confirm%28%27view%27%29%3E&cat=%27%3E%22%3Csvg%2Fonload=confirm%28%27cat%27%29%3E&name=%27%3E%22%3Csvg%2Fonload=confirm%28%27name%27%29%3E&key=%27%3E%22%3Csvg%2Fonload=confirm%28%27key%27%29%3E&p=%27%3E%22%3Csvg%2Fonload=confirm%28%27p%27%29%3E: Top 38 Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests\., "
            r"\[medium\] http://test-php-xss-but-not-on-homepage:80/xss\.php/\?deleted=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-deleted%27%29%3E&search=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-search%27%29%3E&action=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-action%27%29%3E&newname=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-newname%27%29%3E&info=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-info%27%29%3E&content=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-content%27%29%3E&signature=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-signature%27%29%3E&noconfirmation=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-noconfirmation%27%29%3E&field=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-field%27%29%3E&output=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-output%27%29%3E&city=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-city%27%29%3E&rename=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-rename%27%29%3E&mail=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-mail%27%29%3E&term=%27%3E%22%3Csvg%2Fonload=confirm%28%27xss-term%27%29%3E: Fuzzing Parameters - Cross-Site Scripting Cross-site scripting was discovered via a search for reflected parameter values in the server response via GET-requests\.\n, "
            r"\[medium\] http://test-php-xss-but-not-on-homepage:80/xss\.php\?q=testing&s=testing&search=testing\'\"><\d+>&id=testing&lang=testing&keyword=testing&query=testing&page=testing&keywords=testing&year=testing&view=testing&email=testing&type=testing&name=testing&p=testing&month=testing&image=testing&list_type=testing&url=testing&terms=testing&categoryid=testing&key=testing&login=testing&begindate=testing&enddate=testing: Reflected Cross-Site Scripting $",
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
            r"\[high\] http://test-dast-vuln-app:5000\?cat=/etc/passwd&dir=/etc/passwd&action=/etc/passwd&board=/etc/passwd&date=/etc/passwd&detail=/etc/passwd&file=/etc/passwd&filename=/etc/passwd&download=/etc/passwd&path=/etc/passwd&folder=/etc/passwd&prefix=/etc/passwd&include=/etc/passwd&page=/etc/passwd&inc=/etc/passwd&locate=/etc/passwd&show=/etc/passwd&doc=/etc/passwd&site=/etc/passwd&type=/etc/passwd&view=/etc/passwd&content=/etc/passwd&document=/etc/passwd&layout=/etc/passwd&mod=/etc/passwd&conf=/etc/passwd: Local File Inclusion - Linux , "
            r"\[high\] http://test-dast-vuln-app:5000\?cat=abc.html&dir=abc.html&action=abc.html&board=abc.html&date=abc.html&detail=abc.html&file=abc.html&filename=../../../../../../../../../../../../../../../etc/passwd&download=abc.html&path=abc.html&folder=abc.html&prefix=abc.html&include=abc.html&page=abc.html&inc=abc.html&locate=abc.html&show=abc.html&doc=abc.html&site=abc.html&type=abc.html&view=abc.html&content=abc.html&document=abc.html&layout=abc.html&mod=abc.html&conf=abc.html: LFI Detection - Keyed , "
            r"\[medium\] http://test-dast-vuln-app:5000/ssti\?template=Testing'\"><\d+>&q=testing&s=testing&search=testing&id=testing&lang=testing&keyword=testing&query=testing&page=testing&keywords=testing&year=testing&view=testing&email=testing&type=testing&name=testing&p=testing&month=testing&image=testing&list_type=testing&url=testing&terms=testing&categoryid=testing&key=testing&login=testing&begindate=testing&enddate=testing: Reflected Cross-Site Scripting , "
            r"\[medium\] http://test-dast-vuln-app:5000/ssti\?template=Testing{{\d+\*\d+}}&q=testing{{\d+\*\d+}}&s=testing{{\d+\*\d+}}&search=testing{{\d+\*\d+}}&id=testing{{\d+\*\d+}}&lang=testing{{\d+\*\d+}}&keyword=testing{{\d+\*\d+}}&query=testing{{\d+\*\d+}}&page=testing{{\d+\*\d+}}&keywords=testing{{\d+\*\d+}}&year=testing{{\d+\*\d+}}&view=testing{{\d+\*\d+}}&email=testing{{\d+\*\d+}}&type=testing{{\d+\*\d+}}&name=testing{{\d+\*\d+}}&p=testing{{\d+\*\d+}}&month=testing{{\d+\*\d+}}&image=testing{{\d+\*\d+}}&list_type=testing{{\d+\*\d+}}&url=testing{{\d+\*\d+}}&terms=testing{{\d+\*\d+}}&categoryid=testing{{\d+\*\d+}}&key=testing{{\d+\*\d+}}&login=testing{{\d+\*\d+}}&begindate=testing{{\d+\*\d+}}&enddate=testing{{\d+\*\d+}}: Reflected SSTI Arithmetic Based ",
        )
