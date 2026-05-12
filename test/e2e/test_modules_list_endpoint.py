from test.e2e.base import BACKEND_URL, BaseE2ETestCase
from typing import Any, Dict, Optional

import requests

API_TOKEN = "api-token"
VALID_HEADERS: Dict[str, str] = {"X-API-Token": API_TOKEN}


class ModulesListEndpointTestCase(BaseE2ETestCase):
    def test_modules_list_endpoint(self) -> None:
        response = requests.get(f"{BACKEND_URL}/api/get-modules-that-can-be-disabled", headers=VALID_HEADERS)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIsInstance(data, list)

        sql_injection_detector_module: Optional[Dict[str, Any]] = None

        for module in data:
            self.assertIsInstance(module, dict)
            self.assertIn("identity", module)
            self.assertIn("info", module)
            if module["identity"] == "sql_injection_detector":
                sql_injection_detector_module = module

        self.assertTrue(sql_injection_detector_module)
        self.assertEqual(sql_injection_detector_module["identity"], "sql_injection_detector")  # type: ignore
        self.assertContains(sql_injection_detector_module["info"], "🔴 Scanned system load/risk: high.")  # type: ignore
