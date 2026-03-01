from test.base import ArtemisModuleTestCase
from typing import NamedTuple
from unittest.mock import MagicMock

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.js_library_scanner import JSLibraryScanner


class TestData(NamedTuple):
    host: str
    html_content: str
    expected_status: TaskStatus
    expected_libraries: list
    description: str


class JSLibraryScannerTest(ArtemisModuleTestCase):
    karton_class = JSLibraryScanner  # type: ignore

    def test_jquery_vulnerable_version(self) -> None:
        """Test detection of vulnerable jQuery version (CVE-2020-11023)."""
        html = """
        <html>
        <head>
            <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("jQuery 3.4.1", call.kwargs["status_reason"])

        # Check detected libraries
        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertEqual(len(libraries), 1)
        self.assertEqual(libraries[0]["name"], "jQuery")
        self.assertEqual(libraries[0]["version"], "3.4.1")
        self.assertTrue(libraries[0]["vulnerable"])

    def test_jquery_safe_version(self) -> None:
        """Test detection of safe jQuery version."""
        html = """
        <html>
        <head>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

        # Check detected libraries
        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertEqual(len(libraries), 1)
        self.assertEqual(libraries[0]["name"], "jQuery")
        self.assertEqual(libraries[0]["version"], "3.6.0")
        self.assertFalse(libraries[0]["vulnerable"])

    def test_multiple_libraries(self) -> None:
        """Test detection of multiple JavaScript libraries."""
        html = """
        <html>
        <head>
            <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
            <script src="https://unpkg.com/react@16.14.0/umd/react.production.min.js"></script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        # Check detected libraries
        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertEqual(len(libraries), 3)

        # Check jQuery
        jquery_lib = next(lib for lib in libraries if lib["name"] == "jQuery")
        self.assertEqual(jquery_lib["version"], "2.2.4")
        self.assertTrue(jquery_lib["vulnerable"])

        # Check Vue
        vue_lib = next(lib for lib in libraries if lib["name"] == "Vue.js")
        self.assertEqual(vue_lib["version"], "2.6.14")

        # Check React
        react_lib = next(lib for lib in libraries if lib["name"] == "React")
        self.assertEqual(react_lib["version"], "16.14.0")

    def test_inline_jquery_version_comment(self) -> None:
        """Test detection of jQuery version from inline comment."""
        html = """
        <html>
        <head>
            <script>
            /*! jQuery v3.3.1 | (c) JS Foundation and other contributors */
            (function(window){...})(window);
            </script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertEqual(len(libraries), 1)
        self.assertEqual(libraries[0]["name"], "jQuery")
        self.assertEqual(libraries[0]["version"], "3.3.1")
        self.assertTrue(libraries[0]["vulnerable"])

    def test_no_libraries_found(self) -> None:
        """Test when no JavaScript libraries are detected."""
        html = """
        <html>
        <head>
            <script>
            var customCode = function() { return "Hello"; };
            </script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertEqual(len(libraries), 0)

    def test_angular_detection(self) -> None:
        """Test Angular library detection."""
        html = """
        <html>
        <head>
            <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.7.9/angular.min.js"></script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list

        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertEqual(len(libraries), 1)
        self.assertEqual(libraries[0]["name"], "AngularJS")
        self.assertEqual(libraries[0]["version"], "1.7.9")

    def test_http_error_handling(self) -> None:
        """Test handling of HTTP errors."""
        self.mock_db.reset_mock()

        # Mock HTTP error
        self.karton.http_get = MagicMock(side_effect=Exception("Connection failed"))

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.ERROR)

    def test_bootstrap_detection(self) -> None:
        """Test Bootstrap library detection."""
        html = """
        <html>
        <head>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js"></script>
        </head>
        <body>Test</body>
        </html>
        """

        self.mock_db.reset_mock()

        mock_response = MagicMock()
        mock_response.text = html
        mock_response.content = html.encode()
        self.karton.http_get = MagicMock(return_value=mock_response)

        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": "example.com", "port": 80},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list

        libraries = call.kwargs["data"]["detected_libraries"]
        self.assertTrue(any(lib["name"] == "Bootstrap" for lib in libraries))
        bootstrap_lib = next(lib for lib in libraries if lib["name"] == "Bootstrap")
        self.assertEqual(bootstrap_lib["version"], "4.6.0")
