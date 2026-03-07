from unittest.mock import Mock, patch  
from jinja2 import Template  
from test.base import ArtemisModuleTestCase  
  
class TestTaskTemplate(ArtemisModuleTestCase):  
    @patch('artemis.templating.templates.get_template')  
    def test_task_template_with_breadcrumb_navigation(self, mock_get_template):  
        """Test that task template renders breadcrumb navigation correctly"""  
        # Mock template  
        mock_template = Mock()  
        mock_get_template.return_value = mock_template  
          
        # Test data with task path  
        task_data = {  
            "id": "current-task-id",  
            "task": {  
                "uid": "current-task-id",  
                "parent_uid": "parent-task-id",  
                "root_uid": "root-task-id",  
                "headers": {  
                    "type": "SERVICE",  
                    "receiver": "nuclei",  
                    "origin": "classifier"  
                },  
                "priority": "normal"  
            },  
            "target_string": "example.com:80",  
            "analysis_id": "analysis-123",  
            "status": "OK",  
            "status_reason": None,  
            "result": {"test": "data"},  
            "logs": "Task completed successfully"  
        }  
          
        task_path = [  
            {  
                "id": "root-task-id",  
                "task": {  
                    "headers": {"type": "NEW"},  
                    "parent_uid": None  
                },  
                "target_string": "example.com"  
            },  
            {  
                "id": "parent-task-id",   
                "task": {  
                    "headers": {"type": "DOMAIN"},  
                    "parent_uid": "root-task-id"  
                },  
                "target_string": "example.com"  
            }  
        ]  
          
        # Mock template rendering  
        mock_template.render.return_value = """  
        <h4>Full Task Path</h4>  
        <ol class="breadcrumb">  
            <li class="breadcrumb-item">  
                <a href="/task/root-task-id">NEW - example.com</a>  
            </li>  
            <li class="breadcrumb-item">  
                <a href="/task/parent-task-id">DOMAIN - example.com</a>  
            </li>  
        </ol>  
        """  
          
        # Render template  
        from artemis.templating import templates  
        rendered = templates.get_template("task.jinja2").render(  
            request=Mock(),  
            task=task_data,  
            task_path=task_path,  
            referer="/",  
            pretty_printed='{"test": "data"}'  
        )  
          
        # Verify breadcrumb elements exist  
        self.assertIn("Full Task Path", rendered)  
        self.assertIn("breadcrumb", rendered)  
        self.assertIn("root-task-id", rendered)  
        self.assertIn("parent-task-id", rendered)  
        self.assertIn("NEW - example.com", rendered)  
        self.assertIn("DOMAIN - example.com", rendered)  
  
    def test_task_template_with_empty_path(self):  
        """Test template with empty task path"""  
        task_data = {  
            "id": "single-task-id",  
            "task": {  
                "headers": {"type": "NEW"},  
                "parent_uid": None  
            },  
            "target_string": "example.com"  
        }  
          
        # Test with empty path  
        empty_path = []  
          
        # Should render without errors  
        from artemis.templating import templates  
        rendered = templates.get_template("task.jinja2").render(  
            request=Mock(),  
            task=task_data,  
            task_path=empty_path,  
            referer="/",  
            pretty_printed='{}'  
        )  
          
        # Should still have the Full Task Path section  
        self.assertIn("Full Task Path", rendered)  
        self.assertIn("breadcrumb", rendered)  
  
    def test_task_template_preserves_existing_functionality(self):  
        """Test that existing template functionality still works"""  
        task_data = {  
            "id": "test-task-id",  
            "task": {  
                "headers": {  
                    "type": "SERVICE",  
                    "receiver": "nuclei",  
                    "origin": "classifier"  
                },  
                "priority": "high"  
            },  
            "target_string": "example.com:80",  
            "analysis_id": "analysis-123",  
            "status": "ERROR",  
            "status_reason": "Connection timeout",  
            "result": "Error details",  
            "logs": "Task logs"  
        }  
          
        from artemis.templating import templates  
        rendered = templates.get_template("task.jinja2").render(  
            request=Mock(),  
            task=task_data,  
            task_path=[],  
            referer="/",  
            pretty_printed='{"error": "details"}'  
        )  
          
        # Verify existing elements are present  
        self.assertIn("Task results", rendered)  
        self.assertIn("test-task-id", rendered)  
        self.assertIn("nuclei", rendered)  
        self.assertIn("example.com:80", rendered)  
        self.assertIn("ERROR", rendered)  
        self.assertIn("Connection timeout", rendered)  
        self.assertIn("Metadata", rendered)  
        self.assertIn("UID", rendered)  
        self.assertIn("Priority", rendered)  
        self.assertIn("high", rendered)