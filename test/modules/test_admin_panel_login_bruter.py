from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.admin_panel_login_bruter import AdminPanelLoginBruter


class AdminPanelLoginBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = AdminPanelLoginBruter  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-easy-admin-password",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-easy-admin-password:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertEqual(
            call.kwargs["data"]["results"][0]["indicators"], ["redirect", "logout_link", "no_failure_messages"]
        )

    def test_redirect_login(self) -> None:
        """Test that redirect-only login is detected."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-redirect-login",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-redirect-login:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["indicators"], ["redirect", "no_failure_messages"])

    def test_grafana_json_login(self) -> None:
        """Test that JSON API login works against a real Grafana instance (no HTML form)."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-grafana",
                "port": 3000,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertIn("json_api_token", call.kwargs["data"]["results"][0]["indicators"])

    def test_basic_auth_login(self) -> None:
        """Test that an endpoint protected by HTTP Basic auth is detected and brute-forced."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-nginx-basic-auth",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-nginx-basic-auth:80/admin/")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["indicators"], ["http_basic_auth"])

    def test_vendor_default_credential_pair(self) -> None:
        """A login accepting only root:toor proves the credential-pairs mechanism:
        'root' is not in COMMON_USERNAMES, so this is unreachable via the cartesian product."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-root-toor-login",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-root-toor-login:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "root")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "toor")
        self.assertEqual(
            call.kwargs["data"]["results"][0]["indicators"], ["redirect", "logout_link", "no_failure_messages"]
        )

    def test_vendor_default_credential_pair_case_sensitive(self) -> None:
        """A login accepting only Admin:zabbix (capital A) proves pairs pass usernames verbatim:
        COMMON_USERNAMES contains 'admin' (lowercase), so 'Admin' is unreachable via the
        cartesian product and cannot come from case-folding."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-admin-zabbix-login",
                "port": 80,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-admin-zabbix-login:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "Admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "zabbix")
        self.assertEqual(
            call.kwargs["data"]["results"][0]["indicators"], ["redirect", "logout_link", "no_failure_messages"]
        )

    def test_email_field_login(self) -> None:
        """A login form whose identifier field is named/typed 'email' (not 'username')
        must be detected; without the email/type=email heuristic the whole form is
        skipped and nothing is found."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-email-login",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-email-login:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertEqual(
            call.kwargs["data"]["results"][0]["indicators"], ["redirect", "logout_link", "no_failure_messages"]
        )

    def test_autocomplete_field_login(self) -> None:
        """A form with meaningless field names (as generated by SPA frameworks) is
        detected via the autocomplete attribute alone: autocomplete="username" and
        autocomplete="current-password" identify the fields when name and type do not."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-autocomplete-login",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-autocomplete-login:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertEqual(
            call.kwargs["data"]["results"][0]["indicators"], ["redirect", "logout_link", "no_failure_messages"]
        )

    def test_rate_limited_aborts_scan(self) -> None:
        """A target that answers login attempts with HTTP 429 aborts the whole-host
        scan: the status is OK (not INTERESTING), the reason mentions rate limiting,
        and no credentials are reported."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-rate-limited",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertIn("429", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["results"], [])

    def test_rate_limited_during_discovery_aborts(self) -> None:
        """A target that returns HTTP 429 already during path discovery (on the GET
        requests, before brute forcing starts) aborts cleanly: the RateLimitedError
        must be caught in run(), giving status OK with a rate-limit reason and no
        results, rather than crashing the module."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-rate-limited-discovery",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertIn("429", call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["data"]["results"], [])
