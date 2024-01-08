import unittest
from unittest.mock import patch, mock_open, call
from karton.core import Task
import subprocess
from artemis.modules.humble import Humble
from artemis.binds import TaskStatus

class TestHumble(unittest.TestCase):
    def setUp(self):
        self.humble = Humble()

    @patch('subprocess.check_output')
    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}')
    def test_run_with_messages(self, mock_file, mock_run, mock_output):
        mock_output.return_value = b'filename'
        task = Task({"type": "DOMAIN"}, payload={"domain": "test.com"})
        self.humble.run(task)
        mock_output.assert_called_with(
            ["python3", "humble.py", "-u", "https://test.com", "-b", "-o", "json"],
            cwd="/humble",
            stderr=subprocess.DEVNULL,
        )
        mock_run.assert_called_with(["rm", "filename"])
        self.humble.db.save_task_result.assert_called_with(
            task=task, status=TaskStatus.INTERESTING, status_reason='key: value', data={'key': 'value'}
        )

    @patch('subprocess.check_output')
    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data='')
    def test_run_without_messages(self, mock_file, mock_run, mock_output):
        mock_output.return_value = b'filename'
        task = Task({"type": "DOMAIN"}, payload={"domain": "test.com"})
        self.humble.run(task)
        mock_output.assert_called_with(
            ["python3", "humble.py", "-u", "https://test.com", "-b", "-o", "json"],
            cwd="/humble",
            stderr=subprocess.DEVNULL,
        )
        mock_run.assert_called_with(["rm", "filename"])
        self.humble.db.save_task_result.assert_called_with(
            task=task, status=TaskStatus.OK, status_reason=None, data=[]
        )

if __name__ == '__main__':
    unittest.main()