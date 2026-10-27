import copy
import ssl
import unittest
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.port_scanner import PortScanner, TlsCheckResult


def _ssl_error(reason: str, error_class: type[ssl.SSLError] = ssl.SSLError) -> ssl.SSLError:
    error = error_class(1, reason)
    # Set by OpenSSL for real errors; the classification only looks at the reason.
    error.reason = reason
    return error


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

    def _run(self, domains: List[str], tls_checks: Dict[tuple[str, int], TlsCheckResult]) -> MagicMock:
        scanner = MagicMock()
        scanner._scan.return_value = self.scan_results
        scanner.tls_handshake.side_effect = lambda ip, port, domain, retry: tls_checks[(domain, port)]
        tasks = [Task({"type": TaskType.DOMAIN}, payload={TaskType.DOMAIN: domain}) for domain in domains]
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

    def test_name_rejected_http_port_gets_no_service(self) -> None:
        scanner = self._run(
            ["a.example"],
            {("a.example", 443): TlsCheckResult.NAME_REJECTED, ("a.example", 22): TlsCheckResult.NOT_TLS},
        )
        services = self._services(scanner)
        self.assertNotIn(("a.example", 443), services)
        self.assertEqual(services[("a.example", 22)].headers["service"], Service.SSH)
        (result_call,) = scanner.save_task_result.call_args_list
        self.assertIn(
            "443 (service: http ssl: True, version: nginx, not scanned: TLS rejects this name)",
            result_call.kwargs["status_reason"],
        )
        self.assertTrue(result_call.kwargs["data"]["10.0.0.1"]["443"]["ssl"])

    def test_tls_and_inconclusive_results(self) -> None:
        scanner = self._run(
            ["a.example"],
            {("a.example", 443): TlsCheckResult.TLS, ("a.example", 22): TlsCheckResult.UNKNOWN},
        )
        services = self._services(scanner)
        self.assertTrue(services[("a.example", 443)].payload["ssl"])
        # An inconclusive handshake keeps the fingerprintx result
        self.assertFalse(services[("a.example", 22)].payload["ssl"])

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


if __name__ == "__main__":
    unittest.main()
