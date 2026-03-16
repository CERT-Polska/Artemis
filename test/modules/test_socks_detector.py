from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.socks_detector import SocksDetector


class SocksDetectorTest(ArtemisModuleTestCase):
    karton_class = SocksDetector  # type: ignore

    def test_socks5_unauthenticated(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "SOCKS5 proxy on test-socks-open-proxy:1080 allows unauthenticated connections.",
        )
        self.assertEqual(call.kwargs["data"].socks_version, 5)

    def test_socks4_unauthenticated(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"\x05\xff",  # SOCKS5 : no acceptable method (not vulnerable)
            b"\x00\x5a\x00\x50\x7f\x00\x00\x01",  # SOCKS4 : request granted
        ]
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )

        with patch("socket.create_connection", return_value=mock_sock):
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "SOCKS4 proxy on test-socks-open-proxy:1080 allows unauthenticated connections.",
        )
        self.assertEqual(call.kwargs["data"].socks_version, 4)

    def test_no_unauthenticated_access(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"\x05\x02",  # SOCKS5: requires authentication
            b"\x00\x5b\x00\x50\x7f\x00\x00\x01",  # SOCKS4: request rejected
        ]
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )

        with patch("socket.create_connection", return_value=mock_sock):
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
