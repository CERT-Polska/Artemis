from test.base import ArtemisModuleTestCase
from unittest.mock import patch
import os
import socket
import threading
import time

from karton.core import Task
from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei, CUSTOM_TEMPLATES_PATH


class NucleiTest(ArtemisModuleTestCase):
    karton_class = Nuclei  # type: ignore

    def test_severity_threshold(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-service-with-exposed-apache-config",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei": {"severity_threshold": "critical_only"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
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


class NucleiShortTemplateListTest(ArtemisModuleTestCase):
    karton_class = Nuclei  # type: ignore

    def setUp(self) -> None:
        # The patcher MUST start BEFORE super().setUp().
        #
        # super().setUp() instantiates Nuclei via:
        #   self.karton = self.karton_class(config=..., backend=..., db=...)
        #
        # Nuclei.__init__() builds self._template_lists by reading
        # Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN.
        # If the patch is not yet active at that point, __init__ sees the
        # real config (empty override = run all 5584 templates) and caches
        # that full list. Starting the patch afterwards is too late because
        # _template_lists is already built.
        #
        # Starting the patch first means __init__ reads our 5-template
        # override list and caches only those templates.
        #
        # The custom SOCKS template is stored internally by nuclei.py as its
        # full absolute path via os.path.join(CUSTOM_TEMPLATES_PATH, filename).
        # The override check does: `template in OVERRIDE_LIST`, so the list
        # must contain the same full absolute path, not a relative one.
        self.patcher = patch(
            "artemis.config.Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN",
            [
                "http/cves/2020/CVE-2020-28976.yaml",
                "http/vulnerabilities/generic/top-xss-params.yaml",
                "http/vulnerabilities/generic/xss-fuzz.yaml",
                "dast/vulnerabilities/xss/reflected-xss.yaml",
                os.path.join(CUSTOM_TEMPLATES_PATH, "unauthenticated-socks-proxy.yaml"),
            ],
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

        # Nuclei.__init__ now runs with the patched config active.
        super().setUp()

    def test_socks_proxy_detection(self) -> None:
        """
        Starts a mock server on port 1080 that handles two protocols:

        1. HTTP  — Artemis does an HTTP connectivity pre-check before running
                   nuclei. The server returns HTTP 200 so the host is live.
        2. SOCKS5 — The nuclei template sends \\x05\\x01\\x00 and expects
                    \\x05\\x00 back to confirm an unauthenticated proxy.

        The nuclei template hardcodes {{Hostname}}:1080 as the target, so
        the mock server must listen on port 1080 and the task must also use
        port 1080 so the Artemis HTTP pre-check hits our server too.
        """
        ready = threading.Event()
        stop = threading.Event()

        def handle_client(conn: socket.socket) -> None:
            try:
                first = conn.recv(1, socket.MSG_PEEK)
                if not first:
                    return

                if first[0] == 0x05:
                    # SOCKS5 handshake sent by the nuclei template.
                    data = b""
                    while len(data) < 3:
                        chunk = conn.recv(3 - len(data))
                        if not chunk:
                            break
                        data += chunk
                    if data == b"\x05\x01\x00":
                        conn.sendall(b"\x05\x00")  # no-auth accepted
                    # Hold briefly so nuclei can fully read the response.
                    time.sleep(2)
                else:
                    # Plain HTTP pre-check from Artemis — return 200 OK.
                    conn.recv(4096)
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n"
                        b"\r\n"
                    )
            finally:
                conn.close()

        def socks_server() -> None:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", 1080))
            server.listen(10)
            ready.set()

            while not stop.is_set():
                try:
                    server.settimeout(1)
                    conn, _ = server.accept()
                    threading.Thread(
                        target=handle_client, args=(conn,), daemon=True
                    ).start()
                except socket.timeout:
                    continue

            server.close()

        thread = threading.Thread(target=socks_server, daemon=True)
        thread.start()
        ready.wait()

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "127.0.0.1",
                "port": 1080,
            },
        )

        self.run_task(task)
        stop.set()

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

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
