import os
import subprocess
import sys
import tempfile
import typing


class OutputRedirector:
    """
    Replaces stdout and stderr with new streams, that pass the output to original stdout, but also collect
    it so that it can be read via get_output()
    """

    def __init__(self) -> None:
        self._output_collector_file = tempfile.NamedTemporaryFile()
        self._streams = [sys.stdout, sys.stderr]
        self._stream_copy: typing.Dict[int, typing.IO[bytes]] = {}

    def __enter__(self) -> None:
        self._tee = subprocess.Popen(["stdbuf", "-o0", "tee", self._output_collector_file.name], stdin=subprocess.PIPE)

        for stream in self._streams:
            fd = stream.fileno()
            self._stream_copy[fd] = os.fdopen(os.dup(fd), "wb")
            stream.flush()
            os.dup2(self._tee.stdin.fileno(), fd)  # type: ignore

    def __exit__(self, *args: typing.Any) -> None:
        for stream in self._streams:
            fd = stream.fileno()
            stream.flush()
            os.dup2(self._stream_copy[fd].fileno(), fd)
        self._tee.kill()

    def get_output(self) -> bytes:
        self._output_collector_file.seek(0)
        return self._output_collector_file.read()
