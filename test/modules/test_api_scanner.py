from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.api_scanner import APIResult, APIScanner


class APIScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = APIScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-flask-vulnerable-api",
                "port": 5000,
            },
        )

        expected_results = [
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/user/' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
                endpoint="/api/user/' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
                method="GET",
                vulnerable=True,
                vuln_details="Endpoint might be vulnerable to SQli",
                status_code=500,
            ),
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/user/' AND SLEEP(5) --",
                endpoint="/api/user/' AND SLEEP(5) --",
                method="GET",
                vulnerable=True,
                vuln_details="Endpoint might be vulnerable to SQli",
                status_code=500,
            ),
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/ssti",
                endpoint="/api/ssti",
                method="GET",
                vulnerable=True,
                vuln_details="One or more parameter is vulnerable to XSS/HTML Injection Attack",
                status_code=200,
            ),
            APIResult(
                url="http://test-flask-vulnerable-api:5000/api/ssti",
                endpoint="/api/ssti",
                method="GET",
                vulnerable=True,
                vuln_details="One or more parameter is vulnerable to SSTI Attack",
                status_code=200,
            ),
        ]

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(len(call.kwargs["data"]["results"]), len(expected_results))
        for i in range(len(expected_results)):
            self.assertEqual(
                call.kwargs["data"]["results"][i]["url"],
                expected_results[i].url,
            )
            self.assertEqual(
                call.kwargs["data"]["results"][i]["endpoint"],
                expected_results[i].endpoint,
            )
            self.assertEqual(call.kwargs["data"]["results"][i]["method"], expected_results[i].method)
            self.assertEqual(call.kwargs["data"]["results"][i]["vulnerable"], expected_results[i].vulnerable)
            self.assertEqual(call.kwargs["data"]["results"][i]["vuln_details"], expected_results[i].vuln_details)
            self.assertEqual(call.kwargs["data"]["results"][i]["status_code"], expected_results[i].status_code)

    def test_validate_bola_result_true_positive(self) -> None:
        """Test that real BOLA vulnerabilities are correctly identified"""
        scanner = self.karton

        # True BOLA: Same status code (200) with potentially different data
        bola_result = {
            "url": "http://api.example.com/users/123",
            "endpoint": "/users/123",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOLA",
            "response_status_code": 200,
            "response_body": '{"id": 123, "name": "Alice", "email": "alice@example.com"}',
        }

        self.assertTrue(scanner.validate_bola_result(bola_result))

    def test_validate_bola_result_false_positive_forbidden(self) -> None:
        """Test that proper authorization (403) is identified as false positive"""
        scanner = self.karton

        # False positive: Returns 403 Forbidden (proper authorization)
        bola_result = {
            "url": "http://api.example.com/admin/users",
            "endpoint": "/admin/users",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOLA",
            "response_status_code": 403,
            "response_body": '{"error": "Forbidden"}',
        }

        self.assertFalse(scanner.validate_bola_result(bola_result))

    def test_validate_bola_result_false_positive_unauthorized(self) -> None:
        """Test that proper authentication (401) is identified as false positive"""
        scanner = self.karton

        # False positive: Returns 401 Unauthorized (proper auth check)
        bola_result = {
            "url": "http://api.example.com/users/456",
            "endpoint": "/users/456",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOLA",
            "response_status_code": 401,
            "response_body": '{"error": "Unauthorized"}',
        }

        self.assertFalse(scanner.validate_bola_result(bola_result))

    def test_validate_bola_result_false_positive_not_found(self) -> None:
        """Test that 404 responses are identified as false positive"""
        scanner = self.karton

        # False positive: Returns 404 (resource doesn't exist)
        bola_result = {
            "url": "http://api.example.com/users/999",
            "endpoint": "/users/999",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOLA",
            "response_status_code": 404,
            "response_body": '{"error": "Not found"}',
        }

        self.assertFalse(scanner.validate_bola_result(bola_result))

    def test_validate_bopla_result_true_positive(self) -> None:
        """Test that real BOPLA vulnerabilities are correctly identified"""
        scanner = self.karton

        # True BOPLA: Exposes sensitive fields like password, ssn, etc.
        bopla_result = {
            "url": "http://api.example.com/profile",
            "endpoint": "/profile",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOPLA",
            "response_status_code": 200,
            "response_body": '{"name": "John", "password": "secret123", "ssn": "123-45-6789"}',
        }

        self.assertTrue(scanner.validate_bopla_result(bopla_result))

    def test_validate_bopla_result_false_positive_no_sensitive_fields(self) -> None:
        """Test that responses without sensitive fields are identified as false positive"""
        scanner = self.karton

        # False positive: No sensitive fields exposed
        bopla_result = {
            "url": "http://api.example.com/public/info",
            "endpoint": "/public/info",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOPLA",
            "response_status_code": 200,
            "response_body": '{"name": "Public Info", "description": "Available to all"}',
        }

        self.assertFalse(scanner.validate_bopla_result(bopla_result))

    def test_validate_bopla_result_false_positive_forbidden(self) -> None:
        """Test that 403 responses for BOPLA are identified as false positive"""
        scanner = self.karton

        # False positive: Proper authorization prevents access
        bopla_result = {
            "url": "http://api.example.com/admin/secrets",
            "endpoint": "/admin/secrets",
            "method": "GET",
            "vulnerable": True,
            "vuln_details": "Endpoint might be vulnerable to BOPLA",
            "response_status_code": 403,
            "response_body": '{"error": "Access denied"}',
        }

        self.assertFalse(scanner.validate_bopla_result(bopla_result))

    def test_bola_bopla_filtered_from_results(self) -> None:
        """Test that BOLA/BOPLA false positives are filtered from final results"""
        scanner = self.karton

        # Mock the scan method to return BOLA/BOPLA results
        mock_offat_results = {
            "results": [
                {
                    "url": "http://api.example.com/users/1",
                    "endpoint": "/users/1",
                    "method": "GET",
                    "vulnerable": True,
                    "vuln_details": "Endpoint might be vulnerable to BOLA",
                    "response_status_code": 403,  # False positive
                    "response_body": '{"error": "Forbidden"}',
                    "response_headers": {"Content-Type": "application/json"},
                },
                {
                    "url": "http://api.example.com/users/2",
                    "endpoint": "/users/2",
                    "method": "GET",
                    "vulnerable": True,
                    "vuln_details": "Endpoint might be vulnerable to BOLA",
                    "response_status_code": 200,  # True positive
                    "response_body": '{"id": 2, "name": "Bob"}',
                    "response_headers": {"Content-Type": "application/json"},
                },
                {
                    "url": "http://api.example.com/profile",
                    "endpoint": "/profile",
                    "method": "GET",
                    "vulnerable": True,
                    "vuln_details": "Endpoint might be vulnerable to BOPLA",
                    "response_status_code": 200,  # False positive (no sensitive fields)
                    "response_body": '{"name": "Public"}',
                    "response_headers": {"Content-Type": "application/json"},
                },
                {
                    "url": "http://api.example.com/admin/data",
                    "endpoint": "/admin/data",
                    "method": "GET",
                    "vulnerable": True,
                    "vuln_details": "Endpoint might be vulnerable to BOPLA",
                    "response_status_code": 200,  # True positive (has password)
                    "response_body": '{"admin": true, "password": "admin123"}',
                    "response_headers": {"Content-Type": "application/json"},
                },
            ]
        }

        with patch.object(scanner, 'scan', return_value=mock_offat_results):
            with patch.object(scanner, 'discover_spec', return_value=('/tmp/spec.json', 'http://api.example.com/spec')):
                task = Task(
                    {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
                    payload={"host": "api.example.com", "port": 443},
                )

                scanner.run(task)

                (call,) = self.mock_db.save_task_result.call_args_list
                results = call.kwargs["data"]["results"]

                # Should have 2 results: 1 BOLA true positive + 1 BOPLA true positive
                self.assertEqual(len(results), 2)

                # Verify the true positives are present
                endpoints = [r["endpoint"] for r in results]
                self.assertIn("/users/2", endpoints)
                self.assertIn("/admin/data", endpoints)
