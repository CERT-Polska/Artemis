from test.base import ArtemisModuleTestCase
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.cve_lookup import CveLookup


def _make_task(
    cpe: Optional[str] = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    name: str = "Apache HTTP Server",
    version: Optional[str] = "2.4.53",
) -> Task:
    return Task(
        {
            "type": TaskType.WEBAPP,
            "webapp": WebApplication.UNKNOWN.value,
        },
        payload={
            "url": "http://example.test:80",
            "technologies": [
                {
                    "name": name,
                    "version": version,
                    "cpe": cpe,
                    "categories": ["Web servers"],
                },
            ],
        },
    )


def _make_response(payload: Dict[str, Any], status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    return response


_NVD_HIT = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "example vulnerability"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}

# A CVE in a third-party module that only *runs on* Apache: the module is the
# vulnerable component, Apache appears with vulnerable=false. NVD's cpeName query
# returns this when asked about Apache, but it is not an Apache vulnerability.
_NVD_RUNS_ON = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2011-2688",
                "descriptions": [{"lang": "en", "value": "sql injection in a third-party apache module"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:mod_authnz_external_project:"
                                        "mod_authnz_external:*:*:*:*:*:*:*:*",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}

_NVD_MISS: Dict[str, Any] = {"vulnerabilities": []}

NORMALIZED_CPE = "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"


class CveLookupTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = CveLookup  # type: ignore

    def setUp(self) -> None:
        super().setUp()
        self.karton.cache.flush()
        # cve_lookup consumes TaskType.WEBAPP, for which the framework runs a base-URL
        # reachability check before run(). That check issues its own http_requests.get, which
        # the NVD mock below would otherwise intercept; bypass it so each test exercises only
        # the module's NVD path. The live reachability behaviour is covered by the e2e flow.
        connection_check_patcher = patch(
            "artemis.module_base.ArtemisBase.check_connection_to_base_url_and_save_error",
            return_value=True,
        )
        connection_check_patcher.start()
        self.addCleanup(connection_check_patcher.stop)

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_cves_found_yields_interesting(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_response(_NVD_HIT)
        self.run_task(_make_task())

        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        findings = call.kwargs["data"]["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cpe"], NORMALIZED_CPE)
        self.assertEqual(len(findings[0]["cves"]), 1)
        self.assertEqual(findings[0]["cves"][0]["id"], "CVE-2024-1234")
        self.assertEqual(findings[0]["cves"][0]["cvss_score"], 7.5)

        # Confirm the HTTP layer was hit with the normalized (version-filled) CPE
        called_url = mock_get.call_args.args[0]
        self.assertIn("apache%3Ahttp_server%3A2.4.53", called_url)

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_no_cves_yields_ok(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_response(_NVD_MISS)
        self.run_task(_make_task())

        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_runs_on_platform_cve_is_filtered_out(self, mock_get: MagicMock) -> None:
        # NVD returns CVEs where Apache is only a "runs-on" platform (vulnerable=false)
        # for another product's vulnerability. Those must not be reported as Apache CVEs.
        mock_get.return_value = _make_response(_NVD_RUNS_ON)
        self.run_task(_make_task())

        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_cache_hit_skips_http(self, mock_get: MagicMock) -> None:
        self.karton.cache.set(
            NORMALIZED_CPE,
            b'[{"id": "CVE-CACHED", "description": "", "cvss_score": null}]',
        )

        self.run_task(_make_task())

        mock_get.assert_not_called()
        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["findings"][0]["cves"][0]["id"], "CVE-CACHED")

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_second_run_uses_cache(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_response(_NVD_HIT)

        self.run_task(_make_task())
        self.run_task(_make_task())

        self.assertEqual(mock_get.call_count, 1)

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_no_cpe_skips_lookup(self, mock_get: MagicMock) -> None:
        self.run_task(_make_task(cpe=""))

        mock_get.assert_not_called()
        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_http_error_yields_error(self, mock_get: MagicMock) -> None:
        # A failed NVD lookup must not look like a green "no CVEs found": it is saved
        # as ERROR so a transient NVD outage doesn't pass for a clean scan.
        mock_get.side_effect = ConnectionError("nvd unreachable")
        self.run_task(_make_task())

        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.ERROR)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_non_200_status_yields_error(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _make_response({}, status=503)
        self.run_task(_make_task())

        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.ERROR)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_failed_lookup_is_cached(self, mock_get: MagicMock) -> None:
        # The first failure is cached under the CPE key with a short TTL, so a second
        # task for the same technology reports the failure without re-querying NVD.
        mock_get.side_effect = ConnectionError("nvd unreachable")

        self.run_task(_make_task())
        self.run_task(_make_task())

        self.assertEqual(mock_get.call_count, 1)
        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.ERROR)
