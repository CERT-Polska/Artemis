import requests  
from test.e2e.base import BACKEND_URL, BaseE2ETestCase  
  
class TaskPathTestCase(BaseE2ETestCase):  
    def test_task_page_shows_breadcrumb_navigation(self):  
        """Test that task page displays breadcrumb navigation"""  

        self.submit_tasks(["test-domain.com"], "breadcrumb-test")  
        self.wait_for_tasks_finished()  
          

        response = requests.get(  
            f"{BACKEND_URL}api/task-results",  
            headers={"X-API-Token": "api-token"}  
        )  
        tasks = response.json()  
          
        if tasks:  
            task_uid = tasks[0]["task"]["uid"]  
              

            response = requests.get(f"{BACKEND_URL}task/{task_uid}")  
            self.assertEqual(response.status_code, 200)  
              

            self.assertIn("Full Task Path", response.text)  
            self.assertIn("breadcrumb", response.text)  
            self.assertIn("breadcrumb-item", response.text)  
              

            self.assertIn("/task/", response.text)