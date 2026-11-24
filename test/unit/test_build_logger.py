import io
import logging
import unittest

from artemis.utils import CONSOLE_LOG_HANDLER, build_logger


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestBuildLoggerLogsOnce(unittest.TestCase):
    def setUp(self) -> None:
        # The root logger as it is in an Artemis worker: whoisdomain, imported
        # by artemis.utils, calls logging.basicConfig() at import time, which
        # gives the root logger a StreamHandler of its own.
        self.root_capture = _Capture()
        root = logging.getLogger()
        root.addHandler(self.root_capture)
        self.addCleanup(root.removeHandler, self.root_capture)

        self.console = io.StringIO()
        previous_stream = CONSOLE_LOG_HANDLER.stream
        CONSOLE_LOG_HANDLER.setStream(self.console)
        self.addCleanup(CONSOLE_LOG_HANDLER.setStream, previous_stream)

        previous_level = CONSOLE_LOG_HANDLER.level
        CONSOLE_LOG_HANDLER.setLevel(logging.INFO)
        self.addCleanup(CONSOLE_LOG_HANDLER.setLevel, previous_level)

    def _logger(self, name: str) -> logging.Logger:
        logger = build_logger(name)
        logger.setLevel(logging.INFO)
        return logger

    def test_line_printed_once(self) -> None:
        self._logger("artemis.test_build_logger.once").info("PoC minimization: a line")
        self.assertEqual(self.console.getvalue().count("PoC minimization: a line"), 1)
        self.assertEqual(self.root_capture.records, [])

    def test_whoisdomain_style_root_handler_does_not_duplicate(self) -> None:
        """A real basicConfig-style root handler, writing to a stream like
        the worker's stderr, gets nothing."""
        root_stream = io.StringIO()
        handler = logging.StreamHandler(root_stream)
        handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)

        self._logger("artemis.test_build_logger.basic").info("PoC minimization: another line")
        self.assertEqual(root_stream.getvalue(), "")
        self.assertIn("PoC minimization: another line", self.console.getvalue())


if __name__ == "__main__":
    unittest.main()
