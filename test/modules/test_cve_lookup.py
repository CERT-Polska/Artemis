import json
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

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_versionless_technology_is_skipped_not_failed(self, mock_get: MagicMock) -> None:
        # Wappalyzer reports a bare name when it cannot determine the version, leaving the
        # wildcard in the CPE version slot. NVD answers such a cpeName with 404, so the lookup
        # must not be attempted at all - and the task is a clean OK, not an ERROR.
        self.run_task(_make_task(version=None))

        mock_get.assert_not_called()
        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.cve_lookup.http_requests.get")
    def test_paginates_until_total_results_is_reached(self, mock_get: MagicMock) -> None:
        # NVD splits large result sets across startIndex/resultsPerPage pages. Reading only the
        # first page silently drops the rest, so both pages' CVEs must end up in the finding.
        def _page(cve_id: str, start_index: int) -> Dict[str, Any]:
            payload: Dict[str, Any] = json.loads(json.dumps(_NVD_HIT))
            payload["vulnerabilities"][0]["cve"]["id"] = cve_id
            payload["totalResults"] = 2
            payload["resultsPerPage"] = 1
            payload["startIndex"] = start_index
            return payload

        mock_get.side_effect = [
            _make_response(_page("CVE-2024-0001", 0)),
            _make_response(_page("CVE-2024-0002", 1)),
        ]
        self.run_task(_make_task())

        self.assertEqual(mock_get.call_count, 2)
        self.assertIn("startIndex=1", mock_get.call_args_list[1].args[0])

        call = self.mock_db.save_task_result.call_args
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        found = [cve["id"] for cve in call.kwargs["data"]["findings"][0]["cves"]]
        self.assertEqual(found, ["CVE-2024-0001", "CVE-2024-0002"])


class CveLookupIntegrationTest(ArtemisModuleTestCase):
    # Kept in the same module as CveLookupTest on purpose: every test's setUp flushes the shared
    # test Redis, so running cve_lookup tests in a single process keeps that flushing serialized.
    # A separate module would run in its own unittest-parallel process and race the flush.
    karton_class = CveLookup  # type: ignore

    def test_queries_a_real_nvd_endpoint_and_filters_runs_on_cves(self) -> None:
        # Unlike the tests above this one does not patch http_requests: the module makes a real
        # HTTP request to the test-mock-nvd service (CVE_LOOKUP_NVD_API_URL points at it), so it
        # exercises the whole pipeline - the framework reachability check, the throttled request,
        # JSON parsing, vulnerable-component filtering and the saved result.
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={
                "url": "http://test-mock-nvd.local/",
                "technologies": [
                    {
                        "name": "Apache HTTP Server",
                        "version": "2.4.53",
                        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        "categories": ["Web servers"],
                    },
                ],
            },
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        findings = call.kwargs["data"]["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cpe"], "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*")

        # Only the CVE where Apache itself is the vulnerable component survives; the one where
        # Apache is merely the "runs on" platform (CVE-2100-0002) must have been filtered out.
        reported_ids = [cve["id"] for cve in findings[0]["cves"]]
        self.assertEqual(reported_ids, ["CVE-2100-0001"])
        self.assertEqual(findings[0]["cves"][0]["cvss_score"], 9.1)
