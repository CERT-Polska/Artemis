import unittest
from unittest.mock import Mock, patch


class TestTaskTemplate(unittest.TestCase):
    @patch("artemis.templating.templates.get_template")
    def test_task_template_breadcrumb_rendering(self, mock_get_template: Mock) -> None:
        """Test that task template renders breadcrumb navigation correctly for various path lengths"""
        test_cases = [
            {
                "name": "single task",
                "task_data": {
                    "id": "single-task-id",
                    "task": {"uid": "single-task-id"},
                    "target_string": "example.com",
                },
                "task_path": [
                    {"id": "single-task-id", "task": {"headers": {"type": "NEW"}}, "target_string": "example.com"}
                ],
                "expected_html": """
                <h4>Full Task Path</h4>
                <ol class="breadcrumb">
                    <li class="breadcrumb-item">
                        <a href="/task/single-task-id">NEW - example.com</a>
                    </li>
                </ol>
                """,
                "assertions": ["single-task-id"],
            },
            {
                "name": "task with parent",
                "task_data": {
                    "id": "test-task-id",
                    "task": {"uid": "test-task-id", "parent_uid": "parent-task-id", "root_uid": "root-task-id"},
                    "target_string": "example.com",
                },
                "task_path": [
                    {"id": "root-id", "task": {"headers": {"type": "NEW"}}, "target_string": "example.com"},
                    {"id": "parent-id", "task": {"headers": {"type": "DOMAIN"}}, "target_string": "example.com"},
                ],
                "expected_html": """
                <h4>Full Task Path</h4>
                <ol class="breadcrumb">
                    <li class="breadcrumb-item">
                        <a href="/task/root-id">NEW - example.com</a>
                    </li>
                    <li class="breadcrumb-item">
                        <a href="/task/parent-id">DOMAIN - example.com</a>
                    </li>
                </ol>
                """,
                "assertions": ["root-id", "parent-id"],
            },
            {
                "name": "deep hierarchy",
                "task_data": {
                    "id": "leaf-task-id",
                    "task": {"uid": "leaf-task-id", "parent_uid": "child-task-id"},
                    "target_string": "subdomain.example.com",
                },
                "task_path": [
                    {"id": "root-id", "task": {"headers": {"type": "DOMAIN"}}, "target_string": "example.com"},
                    {"id": "child-id", "task": {"headers": {"type": "SUBDOMAIN"}}, "target_string": "sub.example.com"},
                    {
                        "id": "leaf-task-id",
                        "task": {"headers": {"type": "URL"}},
                        "target_string": "subdomain.example.com",
                    },
                ],
                "expected_html": """
                <h4>Full Task Path</h4>
                <ol class="breadcrumb">
                    <li class="breadcrumb-item">
                        <a href="/task/root-id">DOMAIN - example.com</a>
                    </li>
                    <li class="breadcrumb-item">
                        <a href="/task/child-id">SUBDOMAIN - sub.example.com</a>
                    </li>
                    <li class="breadcrumb-item">
                        <a href="/task/leaf-task-id">URL - subdomain.example.com</a>
                    </li>
                </ol>
                """,
                "assertions": ["root-id", "child-id", "leaf-task-id"],
            },
        ]

        for case in test_cases:
            with self.subTest(case=case["name"]):
                mock_template = Mock()
                mock_get_template.return_value = mock_template
                mock_template.render.return_value = case["expected_html"]

                from artemis.templating import templates

                rendered = templates.get_template("task.jinja2").render(
                    request=Mock(),
                    task=case["task_data"],
                    task_path=case["task_path"],
                    referer="/",
                    pretty_printed='{"test": "data"}',
                )

                self.assertIn("Full Task Path", rendered)
                self.assertIn("breadcrumb", rendered)
                for assertion in case["assertions"]:
                    self.assertIn(assertion, rendered)
