import base64
import struct
from test.base import ArtemisModuleTestCase

import requests_mock
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.ntlm_recon import NTLMRecon


def _build_type2_challenge() -> str:
    """Minimal valid NTLMSSP type-2 CHALLENGE with a target-info block."""

    def avpair(t: int, s: str) -> bytes:
        b = s.encode("utf-16le")
        return struct.pack("<hh", t, len(b)) + b

    target_info = (
        avpair(2, "CORP")
        + avpair(1, "DC01")
        + avpair(4, "corp.example.com")
        + avpair(3, "DC01.corp.example.com")
        + avpair(5, "example.com")
        + struct.pack("<hh", 0, 0)
    )
    ti_offset = 56
    msg = b"NTLMSSP\x00"
    msg += struct.pack("<i", 2)
    msg += struct.pack("<hhi", 0, 0, ti_offset)
    msg += struct.pack("<I", 0x00828205)
    msg += b"\x01\x02\x03\x04\x05\x06\x07\x08"
    msg += b"\x00" * 8
    msg += struct.pack("<hhi", len(target_info), len(target_info), ti_offset)
    msg += b"\x00" * 8
    msg += target_info
    return base64.b64encode(msg).decode()


class NTLMReconTest(ArtemisModuleTestCase):
    karton_class = NTLMRecon  # type: ignore

    def test_detects_and_parses_ntlm_endpoint(self) -> None:
        challenge = _build_type2_challenge()

        with requests_mock.Mocker() as m:
            m.head(requests_mock.ANY, status_code=404)
            m.get(requests_mock.ANY, status_code=404)
            m.head(
                "http://test-host:80/EWS/",
                status_code=401,
                headers={"WWW-Authenticate": "NTLM"},
            )
            m.get(
                "http://test-host:80/EWS/",
                status_code=401,
                headers={"WWW-Authenticate": "NTLM " + challenge},
            )

            task = Task(
                {"type": TaskType.SERVICE, "service": Service.HTTP},
                payload={"host": "test-host", "port": 80, "ssl": False},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        endpoints = call.kwargs["data"]["ntlm_endpoints"]
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["url"], "http://test-host:80/EWS/")
        self.assertEqual(endpoints[0]["data"]["AD domain name"], "CORP")
        self.assertEqual(endpoints[0]["data"]["FQDN"], "DC01.corp.example.com")

    def test_no_ntlm_endpoints(self) -> None:
        with requests_mock.Mocker() as m:
            m.head(requests_mock.ANY, status_code=404)
            m.get(requests_mock.ANY, status_code=404)
            task = Task(
                {"type": TaskType.SERVICE, "service": Service.HTTP},
                payload={"host": "test-host", "port": 80, "ssl": False},
            )
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["ntlm_endpoints"], [])
