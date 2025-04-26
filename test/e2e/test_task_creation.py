import json
import requests

from artemis.binds import Service
from test.e2e.base import BaseE2ETestCase, BACKEND_URL
from bs4 import BeautifulSoup
from artemis.binds import TaskType
from artemis.config_registry import ConfigurationRegistry

class TaskCreationTestCase(BaseE2ETestCase):
    def test_task_creation_with_module_config(self) -> None:
        # Test data
        test_config = {
            "severity_threshold": "high_and_above",
            "max_templates": 1000,
            "template_list": ["cves"]
        }
        
        # Create session and get CSRF token
        with requests.Session() as s:
            response = s.get(BACKEND_URL + "add")
            data = response.content
            soup = BeautifulSoup(data, "html.parser")
            csrf_token = soup.find("input", {"name": "csrf_token"})["value"]
            
            # Submit form with module configuration
            response = s.post(
                BACKEND_URL + "add",
                data={
                    "csrf_token": csrf_token,
                    "priority": "normal",
                    "targets": "example.com",
                    "tag": "test-config",
                    "module_name[]": ["nuclei"],
                    "module_config[]": [json.dumps(test_config)]
                }
            )
            self.assertEqual(response.status_code, 301)  # Redirect after success
            
            # Verify task was created with configuration
            task_results = self.get_task_results()
            self.assertTrue(len(task_results["data"]) > 0)
            
            # Get the task details
            task = task_results["data"][0]
            task_id = task[3].split('">')[0].split("/")[-1]  # Extract task ID from link
            
            # Get task details from API
            response = s.get(f"{BACKEND_URL}api/task/{task_id}", headers={"X-API-Token": "api-token"})
            task_data = response.json()
            
            # Verify module configuration was saved
            self.assertIn("module_configs", task_data["task"]["payload"])
            saved_config = task_data["task"]["payload"]["module_configs"]["nuclei"]
            self.assertEqual(saved_config["severity_threshold"], test_config["severity_threshold"])
            self.assertEqual(saved_config["max_templates"], test_config["max_templates"])
            self.assertEqual(saved_config["template_list"], test_config["template_list"])
            
    def test_task_creation_with_invalid_config(self) -> None:
        # Test data with invalid configuration
        invalid_config = {
            "severity_threshold": "invalid_level",
            "max_templates": "not_a_number"
        }
        
        # Create session and get CSRF token
        with requests.Session() as s:
            response = s.get(BACKEND_URL + "add")
            data = response.content
            soup = BeautifulSoup(data, "html.parser")
            csrf_token = soup.find("input", {"name": "csrf_token"})["value"]
            
            # Submit form with invalid configuration
            response = s.post(
                BACKEND_URL + "add",
                data={
                    "csrf_token": csrf_token,
                    "priority": "normal",
                    "targets": "example.com",
                    "tag": "test-invalid-config",
                    "module_name[]": ["nuclei"],
                    "module_config[]": [json.dumps(invalid_config)]
                }
            )
            
            # Should return to form with validation error
            self.assertEqual(response.status_code, 200)
            self.assertIn("Invalid configuration for nuclei", response.text) 