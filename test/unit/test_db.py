import unittest
from unittest.mock import MagicMock, patch
from artemis.db import DB


class TestDB(unittest.TestCase):
    def setUp(self):
        self.db = DB()

    @patch('artemis.db.DB.get_task_by_id')
    def test_get_task_path_single_task(self, mock_get_task_by_id):
        """Test get_task_path for a single task with no parents"""
        task = {
            'id': 'task1',
            'task': {}
        }
        mock_get_task_by_id.return_value = task

        path = self.db.get_task_path('task1')

        self.assertEqual(len(path), 1)
        self.assertEqual(path[0]['id'], 'task1')
        mock_get_task_by_id.assert_called_once_with('task1')

    @patch('artemis.db.DB.get_task_by_id')
    def test_get_task_path_with_parent(self, mock_get_task_by_id):
        """Test get_task_path for a task with one parent"""
        child_task = {
            'id': 'child',
            'task': {'parent_uid': 'parent'}
        }
        parent_task = {
            'id': 'parent',
            'task': {}
        }
        mock_get_task_by_id.side_effect = [child_task, parent_task]

        path = self.db.get_task_path('child')

        self.assertEqual(len(path), 2)
        self.assertEqual(path[0]['id'], 'parent')
        self.assertEqual(path[1]['id'], 'child')
        self.assertEqual(mock_get_task_by_id.call_count, 2)

    @patch('artemis.db.DB.get_task_by_id')
    def test_get_task_path_with_grandparent(self, mock_get_task_by_id):
        """Test get_task_path for a task with grandparent"""
        grandchild = {
            'id': 'grandchild',
            'task': {'parent_uid': 'child'}
        }
        child = {
            'id': 'child',
            'task': {'parent_uid': 'parent'}
        }
        parent = {
            'id': 'parent',
            'task': {}
        }
        mock_get_task_by_id.side_effect = [grandchild, child, parent]

        path = self.db.get_task_path('grandchild')

        self.assertEqual(len(path), 3)
        self.assertEqual(path[0]['id'], 'parent')
        self.assertEqual(path[1]['id'], 'child')
        self.assertEqual(path[2]['id'], 'grandchild')

    @patch('artemis.db.DB.get_task_by_id')
    def test_get_task_path_nonexistent_task(self, mock_get_task_by_id):
        """Test get_task_path for a nonexistent task"""
        mock_get_task_by_id.return_value = None

        path = self.db.get_task_path('nonexistent')

        self.assertEqual(path, [])

    @patch('artemis.db.DB.get_task_by_id')
    def test_get_task_path_broken_chain(self, mock_get_task_by_id):
        """Test get_task_path when parent doesn't exist"""
        child_task = {
            'id': 'child',
            'task': {'parent_uid': 'missing_parent'}
        }
        mock_get_task_by_id.side_effect = [child_task, None]

        path = self.db.get_task_path('child')

        self.assertEqual(len(path), 1)
        self.assertEqual(path[0]['id'], 'child')


if __name__ == '__main__':
    unittest.main()