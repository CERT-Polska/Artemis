import base64
import struct
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

# Candidate endpoints commonly exposing NTLM-over-HTTP, copied verbatim from
# NTLMRecon's built-in wordlist (src/ntlmrecon/misc.py:INTERNAL_WORDLIST;
# https://github.com/pwnfoo/NTLMRecon, MIT-licensed).
#
# Copied rather than imported on purpose: NTLMRecon is not published on PyPI, so
# importing it would mean a git dependency pinned to an archived (0.4 beta)
# project. Its modules are also tangled with its own HTTP/CLI layer
# (requests/urllib3/termcolor/colorama), which we deliberately replaced with
# Artemis' HTTP layer - see the parsing helpers below.
NTLM_PATHS: List[str] = [
    "/abs",
    "/adfs/services/trust/2005/windowstransport",
    "/adfs/ls/wia",
    "/aspnet_client/",
    "/api/",
    "/Autodiscover",
    "/Autodiscover/AutodiscoverService.svc/root",
    "/Autodiscover/Autodiscover.xml",
    "/AutoUpdate/",
    "/CertEnroll/",
    "/CertProv",
    "/CertSrv/",
    "/Conf/",
    "/debug/",
    "/deviceupdatefiles_ext/",
    "/deviceupdatefiles_int/",
    "/dialin",
    "/ecp/",
    "/Etc/",
    "/EWS/",
    "/Exchange/",
    "/Exchweb/",
    "/GroupExpansion/",
    "/HybridConfig",
    "/iwa/authenticated.aspx",
    "/iwa/iwa_test.aspx",
    "/mcx",
    "/meet",
    "/Microsoft-Server-ActiveSync/",
    "/OAB/",
    "/ocsp/",
    "/owa/",
    "/PersistentChat",
    "/PhoneConferencing/",
    "/PowerShell/",
    "/Public/",
    "/Reach/sip.svc",
    "/reports/",
    "/RequestHandler/",
    "/RequestHandlerExt",
    "/RequestHandlerExt/",
    "/Rgs/",
    "/RgsClients",
    "/Rpc/",
    "/RpcWithCert/",
    "/scheduler",
    "/sso",
    "/Ucwa",
    "/UnifiedMessaging/",
    "/WebTicket",
    "/WebTicket/WebTicketService.svc",
    "/_windows/default.aspx?ReturnUrl=/",
]

# Static NTLM type-1 (NEGOTIATE) message used by NTLMRecon to elicit a type-2
# CHALLENGE carrying the target-info block.
NTLM_NEGOTIATE_HEADER = "NTLM TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw=="

# NTLMSSP target-info (AV_PAIR) id -> human label, using NTLMRecon's naming.
TARGET_FIELD_TYPES: Dict[int, str] = {
    1: "Server name",
    2: "AD domain name",
    3: "FQDN",
    4: "DNS domain name",
    5: "Parent DNS domain",
}


# The NTLM type-1 construction and the NTLMSSP type-2 (CHALLENGE) target-info
# parsing below are reimplemented from NTLMRecon (src/ntlmrecon/ntlmutil.py,
# MIT-licensed). They are not imported because the upstream helper
# (gather_ntlm_info) performs the HTTP request itself and is coupled to
# requests/urllib3 - there is no pure "parse these challenge bytes" function to
# reuse. The protocol logic is reimplemented here and driven by Artemis'
# throttled HTTP layer instead.
def extract_ntlm_token(www_authenticate: str) -> Optional[str]:
    for part in www_authenticate.split(","):
        part = part.strip()
        if part.upper().startswith("NTLM"):
            token = part[len("NTLM") :].strip()
            if token:
                return token
    return None


def parse_ntlm_challenge(b64_challenge: str) -> Optional[Dict[str, str]]:
    try:
        raw_msg = base64.b64decode(b64_challenge)
    except Exception:
        return None

    if raw_msg[:7] != b"NTLMSSP":
        return None

    descriptor = raw_msg[40:48]
    if len(descriptor) != 8:
        return None

    length, _alloc, offset = struct.unpack("<hhi", descriptor)
    block = raw_msg[offset : offset + length]

    parsed: Dict[str, str] = {}
    pos = 0
    while pos + 4 <= len(block):
        rec_type_id, rec_sz = struct.unpack("<hh", block[pos : pos + 4])
        if rec_type_id == 0:
            break
        value = block[pos + 4 : pos + 4 + rec_sz].decode("utf-8", errors="ignore").replace("\x00", "")
        label = TARGET_FIELD_TYPES.get(rec_type_id)
        if label:
            parsed[label] = value
        pos += 4 + rec_sz

    return parsed or None


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class NTLMRecon(ArtemisBase):
    identity = "ntlm_recon"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _probe(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            head = http_requests.request(
                "head",
                url,
                allow_redirects=False,
                requests_per_second=self.requests_per_second_for_current_tasks,
            )
        except Exception:
            return None

        if head.status_code != 401:
            return None
        if "NTLM" not in head.headers.get("WWW-Authenticate", "").upper():
            return None

        try:
            challenge_response = http_requests.request(
                "get",
                url,
                allow_redirects=False,
                headers={"Authorization": NTLM_NEGOTIATE_HEADER},
                requests_per_second=self.requests_per_second_for_current_tasks,
            )
        except Exception:
            return {"url": url, "data": {}, "decoded": False}

        token = extract_ntlm_token(challenge_response.headers.get("WWW-Authenticate", ""))
        data = parse_ntlm_challenge(token) if token else None
        return {"url": url, "data": data or {}, "decoded": bool(data)}

    def run(self, current_task: Task) -> None:
        base_url = get_target_url(current_task).rstrip("/")
        self.log.info("ntlm_recon scanning %s", base_url)

        endpoints: List[Dict[str, Any]] = []
        for path in NTLM_PATHS:
            url = base_url + "/" + path.lstrip("/")
            info = self._probe(url)
            if info:
                endpoints.append(info)

        if endpoints:
            status = TaskStatus.INTERESTING
            status_reason = "Found exposed NTLM authentication endpoint(s): " + ", ".join(e["url"] for e in endpoints)
        else:
            status = TaskStatus.OK
            status_reason = "No exposed NTLM authentication endpoints found."

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"ntlm_endpoints": endpoints},
        )


if __name__ == "__main__":
    NTLMRecon.parallel_loop()
