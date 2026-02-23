"""Tests verifying that frontend proxy endpoints use async I/O (aiohttp) instead of
blocking requests, preventing event loop starvation in production."""

import ast
import unittest
from pathlib import Path

FRONTEND_PATH = Path(__file__).resolve().parents[2] / "artemis" / "frontend.py"


class TestFrontendNoBlockingIO(unittest.TestCase):
    """Static analysis tests ensuring frontend.py doesn't use blocking requests in async functions."""

    source: str
    tree: ast.Module

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = FRONTEND_PATH.read_text()
        cls.tree = ast.parse(cls.source)

    def _get_async_function(self, name: str) -> ast.AsyncFunctionDef:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == name:
                return node
        self.fail(f"async function '{name}' not found in frontend.py")

    def _find_calls_in_function(self, func: ast.AsyncFunctionDef) -> list[str]:
        """Return dotted call names (e.g. 'requests.get') found in a function body."""
        calls = []
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    calls.append(f"{node.func.value.id}.{node.func.attr}")
        return calls

    def test_no_blocking_requests_import(self) -> None:
        """frontend.py must not import the blocking 'requests' library."""
        for node in ast.iter_child_nodes(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(
                        alias.name,
                        "requests",
                        "frontend.py imports blocking 'requests' library — use aiohttp instead",
                    )

    def test_karton_dashboard_uses_aiohttp_not_requests(self) -> None:
        """karton_dashboard must use aiohttp (async), not requests (blocking)."""
        func = self._get_async_function("karton_dashboard")
        calls = self._find_calls_in_function(func)
        self.assertTrue(
            any("aiohttp" in c or "session" in c for c in calls),
            f"karton_dashboard should use aiohttp, found calls: {calls}",
        )
        for call in calls:
            self.assertFalse(
                call.startswith("requests."),
                f"karton_dashboard uses blocking '{call}' — must use aiohttp",
            )

    def test_prometheus_uses_aiohttp_not_requests(self) -> None:
        """prometheus must use aiohttp (async), not requests (blocking)."""
        func = self._get_async_function("prometheus")
        calls = self._find_calls_in_function(func)
        self.assertTrue(
            any("aiohttp" in c or "session" in c for c in calls),
            f"prometheus should use aiohttp, found calls: {calls}",
        )
        for call in calls:
            self.assertFalse(
                call.startswith("requests."),
                f"prometheus uses blocking '{call}' — must use aiohttp",
            )

    def test_karton_dashboard_has_timeout(self) -> None:
        """karton_dashboard must set an explicit timeout to prevent indefinite hangs."""
        func = self._get_async_function("karton_dashboard")
        source_lines = ast.get_source_segment(self.source, func)
        assert source_lines is not None
        self.assertIn(
            "timeout",
            source_lines,
            "karton_dashboard must set an explicit timeout on the aiohttp request",
        )

    def test_prometheus_has_timeout(self) -> None:
        """prometheus must set an explicit timeout to prevent indefinite hangs."""
        func = self._get_async_function("prometheus")
        source_lines = ast.get_source_segment(self.source, func)
        assert source_lines is not None
        self.assertIn(
            "timeout",
            source_lines,
            "prometheus must set an explicit timeout on the aiohttp request",
        )

    def test_no_merge_conflict_markers(self) -> None:
        """Source file must not contain unresolved merge conflict markers."""
        for marker in ["<<<<<<<", "=======", ">>>>>>>"]:
            self.assertNotIn(marker, self.source, f"Unresolved merge conflict marker found: {marker}")


if __name__ == "__main__":
    unittest.main()
