import copy
import functools
import ipaddress
import ssl
import unittest
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import requests
from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.http_requests import HTTPResponse
from artemis.modules.port_scanner import PortScanner, TlsCheckResult

# The 400s nginx 1.29.0 and Apache 2.4.56 with mod_ssl answer a plain HTTP request to their TLS port with
NGINX_HTTPS_PORT_ERROR = (
    "<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n<body>\r\n"
    "<center><h1>400 Bad Request</h1></center>\r\n<center>The plain HTTP request was sent to HTTPS port</center>\r\n"
    "<hr><center>nginx/1.29.0</center>\r\n</body>\r\n</html>\r\n"
)
APACHE_HTTPS_PORT_ERROR = (
    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>400 Bad Request</title>\n'
    "</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand."
    "<br />\nReason: You're speaking plain HTTP to an SSL-enabled server port.<br />\n Instead use the HTTPS scheme "
    "to access this URL, please.<br />\n</p>\n</body></html>\n"
)


def _ssl_error(reason: str, error_class: type[ssl.SSLError] = ssl.SSLError) -> ssl.SSLError:
    error = error_class(1, reason)
    # Set by OpenSSL for real errors; the classification only looks at the reason.
    error.reason = reason
    return error


def _http_response(status_code: int, body: str) -> HTTPResponse:
    return HTTPResponse(
        status_code=status_code,
        content_bytes=body.encode(),
        encoding="utf-8",
        is_redirect=False,
        url="http://10.0.0.1:443/",
        headers={},
    )


def _task(target: str) -> Task:
    try:
        ipaddress.ip_address(target)
        task_type = TaskType.IP
    except ValueError:
        task_type = TaskType.DOMAIN
    return Task({"type": task_type}, payload={task_type: target})


def _tls_check(
    wrap_socket_side_effect: Any = None, connect_side_effect: Any = None, retry: bool = False
) -> Tuple[TlsCheckResult, MagicMock, MagicMock]:
    """Returns the result of PortScanner.tls_handshake, the mocked socket.create_connection and the scanner."""
    scanner = MagicMock()
    with (
        patch("artemis.modules.port_scanner.socket.create_connection") as create_connection,
        patch("artemis.modules.port_scanner.SSL_CONTEXT") as ssl_context,
    ):
        create_connection.side_effect = connect_side_effect
        ssl_context.wrap_socket.side_effect = wrap_socket_side_effect
        result = PortScanner.tls_handshake(scanner, ip="127.0.0.1", port=443, domain="example.com", retry=retry)
    return result, create_connection, scanner


class TestTlsHandshake(unittest.TestCase):
    """The reasons below are the ones OpenSSL gives for the respective situations (checked against nginx with
    ssl_reject_handshake, servers that support only TLS 1.0 or 1.1, a plain HTTP server and an SSH server; the
    refused ServerHellos against a minimal server that sends them)."""

    def _check(self, wrap_socket_side_effect: Any = None, connect_side_effect: Any = None) -> TlsCheckResult:
        return _tls_check(wrap_socket_side_effect, connect_side_effect)[0]

    def test_successful_handshake_is_tls(self) -> None:
        self.assertEqual(self._check(), TlsCheckResult.TLS)

    def test_unrecognized_name_alert_is_name_rejected(self) -> None:
        self.assertEqual(
            self._check(wrap_socket_side_effect=_ssl_error("TLSV1_UNRECOGNIZED_NAME")), TlsCheckResult.NAME_REJECTED
        )

    def test_wrong_version_number_is_not_tls(self) -> None:
        """What OpenSSL reports when the port answers with plain HTTP or an SSH banner."""
        self.assertEqual(
            self._check(wrap_socket_side_effect=_ssl_error("WRONG_VERSION_NUMBER")), TlsCheckResult.NOT_TLS
        )

    def test_other_alert_is_tls(self) -> None:
        self.assertEqual(
            self._check(wrap_socket_side_effect=_ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE")), TlsCheckResult.TLS
        )

    def test_protocol_version_alert_is_tls(self) -> None:
        """What nginx and openssl s_server limited to TLS 1.0 or 1.1 answer, as the client requires TLS 1.2."""
        self.assertEqual(
            self._check(wrap_socket_side_effect=_ssl_error("TLSV1_ALERT_PROTOCOL_VERSION")), TlsCheckResult.TLS
        )

    def test_server_hello_with_old_version_is_tls(self) -> None:
        """A server that answers with a TLS 1.0, TLS 1.1 or SSL 3.0 ServerHello instead of an alert."""
        self.assertEqual(self._check(wrap_socket_side_effect=_ssl_error("UNSUPPORTED_PROTOCOL")), TlsCheckResult.TLS)

    def test_server_hello_without_secure_renegotiation_is_tls(self) -> None:
        """A server without support for secure renegotiation (RFC 5746), which this client requires."""
        self.assertEqual(
            self._check(wrap_socket_side_effect=_ssl_error("UNSAFE_LEGACY_RENEGOTIATION_DISABLED")),
            TlsCheckResult.TLS,
        )

    def test_closed_connection_is_unknown(self) -> None:
        self.assertEqual(
            self._check(wrap_socket_side_effect=_ssl_error("UNEXPECTED_EOF_WHILE_READING", ssl.SSLEOFError)),
            TlsCheckResult.UNKNOWN,
        )

    def test_timeout_is_unknown(self) -> None:
        self.assertEqual(self._check(wrap_socket_side_effect=TimeoutError()), TlsCheckResult.UNKNOWN)

    def test_refused_connection_is_unknown(self) -> None:
        self.assertEqual(self._check(connect_side_effect=ConnectionRefusedError()), TlsCheckResult.UNKNOWN)


class TestTlsHandshakeRetry(unittest.TestCase):
    def test_unknown_then_tls_is_tls(self) -> None:
        result, create_connection, scanner = _tls_check(
            connect_side_effect=[TimeoutError("timed out"), MagicMock()], retry=True
        )
        self.assertEqual(result, TlsCheckResult.TLS)
        self.assertEqual(create_connection.call_count, 2)
        scanner.log.info.assert_not_called()

    def test_unknown_twice_is_unknown_and_logged(self) -> None:
        result, create_connection, scanner = _tls_check(connect_side_effect=TimeoutError("timed out"), retry=True)
        self.assertEqual(result, TlsCheckResult.UNKNOWN)
        self.assertEqual(create_connection.call_count, 2)
        scanner.log.info.assert_called_once()
        log_arguments = scanner.log.info.call_args.args[1:]
        for expected in ["example.com", "127.0.0.1", 443, "TimeoutError: timed out"]:
            self.assertIn(expected, log_arguments)

    def test_conclusive_result_is_not_retried(self) -> None:
        for wrap_socket_side_effect, expected in [
            (None, TlsCheckResult.TLS),
            (_ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE"), TlsCheckResult.TLS),
            (_ssl_error("TLSV1_UNRECOGNIZED_NAME"), TlsCheckResult.NAME_REJECTED),
            (_ssl_error("WRONG_VERSION_NUMBER"), TlsCheckResult.NOT_TLS),
        ]:
            with self.subTest(expected=expected, error=wrap_socket_side_effect):
                result, create_connection, scanner = _tls_check(
                    wrap_socket_side_effect=wrap_socket_side_effect, retry=True
                )
                self.assertEqual(result, expected)
                self.assertEqual(create_connection.call_count, 1)
                scanner.log.info.assert_not_called()

    def test_unknown_without_retry_is_neither_retried_nor_logged(self) -> None:
        result, create_connection, scanner = _tls_check(connect_side_effect=TimeoutError("timed out"), retry=False)
        self.assertEqual(result, TlsCheckResult.UNKNOWN)
        self.assertEqual(create_connection.call_count, 1)
        scanner.log.info.assert_not_called()


class TestRunMultipleUsesTlsCheck(unittest.TestCase):
    SCAN_RESULTS: Dict[str, Dict[str, Dict[str, Any]]] = {
        "10.0.0.1": {
            "443": {"service": "http", "ssl": False, "version": "nginx"},
            "22": {"service": "ssh", "ssl": False, "version": "N/A"},
        }
    }

    def _run(
        self,
        targets: List[str],
        tls_checks: Dict[tuple[str, int], TlsCheckResult],
        plain_http: HTTPResponse | Exception = _http_response(400, NGINX_HTTPS_PORT_ERROR),
    ) -> MagicMock:
        """Runs a batch of tasks (an IP task for an IP, a domain task otherwise) that all resolve to 10.0.0.1.
        plain_http is what a plain HTTP request gets: a response or an exception."""
        scanner = MagicMock()
        scanner._scan.return_value = self.scan_results
        scanner.tls_handshake.side_effect = lambda ip, port, domain, retry: tls_checks[(domain, port)]
        scanner.plain_http_gets_https_port_error = functools.partial(
            PortScanner.plain_http_gets_https_port_error, scanner
        )
        if isinstance(plain_http, Exception):
            scanner.http_get.side_effect = plain_http
        else:
            scanner.http_get.return_value = plain_http
        tasks = [_task(target) for target in targets]
        with patch("artemis.modules.port_scanner.lookup", return_value={"10.0.0.1"}):
            PortScanner.run_multiple(scanner, tasks)
        return scanner

    def setUp(self) -> None:
        self.scan_results = copy.deepcopy(self.SCAN_RESULTS)

    @staticmethod
    def _services(scanner: MagicMock) -> Dict[tuple[str, int], Task]:
        services = {}
        for call in scanner.add_task.call_args_list:
            new_task = call.args[1]
            services[(new_task.payload["host"], new_task.payload["port"])] = new_task
        return services

    NAME_REJECTED_ON_443 = {("a.example", 443): TlsCheckResult.NAME_REJECTED, ("a.example", 22): TlsCheckResult.NOT_TLS}

    def test_name_rejected_http_port_gets_no_service_if_plain_http_gets_the_https_port_error(self) -> None:
        for server, body in [("nginx", NGINX_HTTPS_PORT_ERROR), ("Apache", APACHE_HTTPS_PORT_ERROR)]:
            with self.subTest(server=server):
                scanner = self._run(["a.example"], self.NAME_REJECTED_ON_443, plain_http=_http_response(400, body))
                services = self._services(scanner)
                self.assertNotIn(("a.example", 443), services)
                self.assertEqual(services[("a.example", 22)].headers["service"], Service.SSH)
                (result_call,) = scanner.save_task_result.call_args_list
                self.assertIn(
                    "443 (service: http ssl: True, version: nginx, not scanned: TLS rejects this name)",
                    result_call.kwargs["status_reason"],
                )
                self.assertTrue(result_call.kwargs["data"]["10.0.0.1"]["443"]["ssl"])
                scanner.http_get.assert_called_once_with(
                    "http://10.0.0.1:443/", headers={"Host": "a.example"}, allow_redirects=False, timeout=3.0
                )
                scanner.log.info.assert_called_once()

    def test_name_rejected_http_port_gets_a_service_without_tls_if_plain_http_gets_another_answer(self) -> None:
        """E.g. a port where a multiplexer (sslh, HAProxy) passes plain HTTP to another backend than TLS."""
        answers: List[HTTPResponse | Exception] = [
            _http_response(200, "<html>a.example</html>"),
            _http_response(301, ""),
            _http_response(400, "Bad Request"),
            # The status matters too, e.g. for a page that quotes the error
            _http_response(200, NGINX_HTTPS_PORT_ERROR),
            requests.ConnectionError("Connection aborted."),
            requests.Timeout("Read timed out."),
        ]
        for answer in answers:
            with self.subTest(answer=answer):
                scanner = self._run(["a.example"], self.NAME_REJECTED_ON_443, plain_http=answer)
                service = self._services(scanner)[("a.example", 443)]
                self.assertEqual(service.headers["service"], Service.HTTP)
                self.assertFalse(service.payload["ssl"])
                (result_call,) = scanner.save_task_result.call_args_list
                self.assertIn("443 (service: http ssl: False, version: nginx)", result_call.kwargs["status_reason"])
                self.assertNotIn("not scanned", result_call.kwargs["status_reason"])
                self.assertFalse(result_call.kwargs["data"]["10.0.0.1"]["443"]["ssl"])
                scanner.log.info.assert_called_once()

    def test_plain_http_is_checked_only_for_a_name_rejected_http_port(self) -> None:
        scanner = self._run(
            ["a.example", "b.example"],
            {
                ("a.example", 443): TlsCheckResult.TLS,
                ("a.example", 22): TlsCheckResult.NAME_REJECTED,
                ("b.example", 443): TlsCheckResult.UNKNOWN,
                ("b.example", 22): TlsCheckResult.NOT_TLS,
            },
        )
        scanner.http_get.assert_not_called()

    def test_tls_and_inconclusive_results(self) -> None:
        scanner = self._run(
            ["a.example"],
            {("a.example", 443): TlsCheckResult.TLS, ("a.example", 22): TlsCheckResult.UNKNOWN},
        )
        services = self._services(scanner)
        self.assertTrue(services[("a.example", 443)].payload["ssl"])
        # An inconclusive handshake keeps the fingerprintx result
        self.assertFalse(services[("a.example", 22)].payload["ssl"])

    def test_inconclusive_result_keeps_tls_reported_by_fingerprintx(self) -> None:
        self.scan_results["10.0.0.1"]["443"]["ssl"] = True
        scanner = self._run(
            ["a.example"],
            {("a.example", 443): TlsCheckResult.UNKNOWN, ("a.example", 22): TlsCheckResult.NOT_TLS},
        )
        self.assertTrue(self._services(scanner)[("a.example", 443)].payload["ssl"])
        (result_call,) = scanner.save_task_result.call_args_list
        self.assertIn("443 (service: http ssl: True, version: nginx)", result_call.kwargs["status_reason"])
        self.assertTrue(result_call.kwargs["data"]["10.0.0.1"]["443"]["ssl"])

    def test_retry_only_for_http_ports(self) -> None:
        scanner = self._run(
            ["a.example"],
            {("a.example", 443): TlsCheckResult.UNKNOWN, ("a.example", 22): TlsCheckResult.UNKNOWN},
        )
        retry_per_port = {call.kwargs["port"]: call.kwargs["retry"] for call in scanner.tls_handshake.call_args_list}
        self.assertEqual(retry_per_port, {443: True, 22: False})

    def test_domains_on_the_same_ip_dont_share_the_tls_result(self) -> None:
        scanner = self._run(
            ["a.example", "b.example"],
            {
                ("a.example", 443): TlsCheckResult.TLS,
                ("a.example", 22): TlsCheckResult.NOT_TLS,
                ("b.example", 443): TlsCheckResult.NAME_REJECTED,
                ("b.example", 22): TlsCheckResult.NOT_TLS,
            },
        )
        services = self._services(scanner)
        self.assertTrue(services[("a.example", 443)].payload["ssl"])
        self.assertNotIn(("b.example", 443), services)
        result_a, result_b = scanner.save_task_result.call_args_list
        self.assertNotIn("not scanned", result_a.kwargs["status_reason"])
        self.assertIn("not scanned", result_b.kwargs["status_reason"])
        # The scan results shared by both tasks are left as fingerprintx reported them
        self.assertEqual(self.scan_results, self.SCAN_RESULTS)

    def test_ip_task_after_a_domain_task_on_that_ip_keeps_the_fingerprintx_result(self) -> None:
        scanner = self._run(
            ["a.example", "10.0.0.1"],
            {("a.example", 443): TlsCheckResult.TLS, ("a.example", 22): TlsCheckResult.NOT_TLS},
        )
        services = self._services(scanner)
        self.assertTrue(services[("a.example", 443)].payload["ssl"])
        self.assertFalse(services[("10.0.0.1", 443)].payload["ssl"])
        _, result_ip = scanner.save_task_result.call_args_list
        self.assertIn("443 (service: http ssl: False, version: nginx)", result_ip.kwargs["status_reason"])


if __name__ == "__main__":
    unittest.main()
