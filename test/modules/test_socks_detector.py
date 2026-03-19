from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.socks_detector import SocksDetector


def _make_sock(recv_response: bytes) -> MagicMock:
    sock = MagicMock()
    sock.recv.return_value = recv_response
    sock.__enter__ = lambda s: s
    sock.__exit__ = MagicMock(return_value=False)
    return sock


class SocksDetectorTest(ArtemisModuleTestCase):
    karton_class = SocksDetector  # type: ignore

    def test_socks5_unauthenticated(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )
        self.run_task(task)
        (call_,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call_.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call_.kwargs["status_reason"],
            "SOCKS5 proxy on test-socks-open-proxy:1080 allows unauthenticated connections.",
        )
        self.assertEqual(call_.kwargs["data"].socks_version, 5)

    def test_socks4_unauthenticated(self) -> None:
        socks5_sock = _make_sock(b"\x05\xff")  # no acceptable method
        socks4_sock = _make_sock(b"\x00\x5a\x00\x50\x7f\x00\x00\x01")  # request granted

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )

        with patch("socket.create_connection", side_effect=[socks5_sock, socks4_sock]):
            self.run_task(task)

        (call_,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call_.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call_.kwargs["status_reason"],
            "SOCKS4 proxy on test-socks-open-proxy:1080 allows unauthenticated connections.",
        )
        self.assertEqual(call_.kwargs["data"].socks_version, 4)

    def test_no_unauthenticated_access(self) -> None:
        socks5_sock = _make_sock(b"\x05\x02")  # requires authentication
        socks4_sock = _make_sock(b"\x00\x5b\x00\x50\x7f\x00\x00\x01")  # request rejected

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.SOCKS},
            payload={"host": "test-socks-open-proxy", "port": 1080},
        )

        with patch("socket.create_connection", side_effect=[socks5_sock, socks4_sock]):
            self.run_task(task)

        (call_,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call_.kwargs["status"], TaskStatus.OK)
