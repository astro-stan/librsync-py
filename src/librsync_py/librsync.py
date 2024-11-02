# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync stream API."""

from __future__ import annotations

import io
from sys import version_info
from threading import Lock
from typing import TYPE_CHECKING, Any

from librsync_py import RsResult
from librsync_py._internals.wrappers import JobStats, get_job_stats, job_iter

if version_info < (3, 11):  # pragma: no cover
    from typing_extensions import Self
else:  # pragma: no cover
    from typing import Self

if TYPE_CHECKING:  # pragma: no cover
    from cffi.backend_ctypes import CTypesData  # type: ignore[import-untyped]


class Job(io.BufferedIOBase):
    """Librsync job wrapper."""

    def __init__(
        self: Self,
        job: CTypesData,
        raw: io.RawIOBase,
        buffer_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> None:
        """Create librsync job from a readable raw IO object."""
        if not raw.readable():
            msg = '"raw" argument must be readable.'
            raise OSError(msg)

        self._raw = raw
        self.__job = job

        if buffer_size <= 0:
            msg = "invalid buffer size"
            raise ValueError(msg)
        self.buffer_size = buffer_size

        self._raw_buf = b""
        self._buf = bytearray()
        self._read_lock = Lock()

    def readable(self: Self) -> bool:
        """Check if the stream is readeable."""
        return self.raw.readable()

    def read(self: Self, size: int | None = -1) -> bytes:
        """Read from stream."""
        return self._read_unlocked(size)

    def close(self: Self) -> None:
        """Close stream."""
        if self.raw is not None and not self.closed:
            self.raw.close()

    def detach(self: Self) -> io.RawIOBase:
        """Detach from the underlying stream and return it."""
        if self.raw is None:
            msg = "raw stream already detached"
            raise ValueError(msg)
        raw = self._raw
        self._raw = None
        return raw

    def _read_unlocked(self: Self, size: int | None = -1) -> bytes:
        """Read from the stream, without thread safety.

        :param size: The maximum amount of bytes to read.
        :type size: Optional[int]
        :returns: The read data.
        :rtype: bytes
        :raises RsCApiError: If something goes wrong during the read.
        :raises ValueError: If input param validation fails.
        """
        if size is None:
            size = -1

        if size == 0:
            return b""

        if len(self._buf) >= size and size >= 0:
            out = self._buf[:size]
            self._buf = self._buf[size:]
            return bytes(out)

        chunks = [self._buf]
        total_length = len(self._buf)

        chunk_size = max(self.buffer_size, size)
        c_buffer = bytearray(chunk_size)

        result = RsResult.BLOCKED
        with memoryview(c_buffer) as mv:
            while result == RsResult.BLOCKED:
                result, written = self._readinto_unlocked(mv)
                chunks.append(mv[:written].tobytes())
                total_length += written
                if total_length >= size and size >= 0:
                    break

        self._buf = bytearray().join(chunks)

        if size < 0:
            size = len(self._buf)

        out = self._buf[:size]
        self._buf = self._buf[size:]
        return bytes(out)

    def _readinto_unlocked(self: Self, buf: memoryview) -> tuple[RsResult, int]:
        """Read from the stream into a buffer, without thread safety.

        :param buf: The buffer to store the read data into.
        :type buf: memoryview
        :returns: The result of the operation and the bytes written to the buffer.
        :rtype: tuple[RsResult, int]
        :raises RsCApiError: If something goes wrong during the read.
        :raises ValueError: If input param validation fails.
        """
        out_pos = 0
        out_cap = len(buf)

        result = RsResult.BLOCKED
        while result == RsResult.BLOCKED and out_cap > 0:
            self._raw_buf += self.raw.read(max(out_cap - len(self._raw_buf), 0))
            cap = len(self._raw_buf)

            with memoryview(self._raw_buf) as ib:
                result, read, written = job_iter(
                    self.__job,
                    ib,
                    buf[out_pos:],
                    eof=not bool(cap),
                )

            self._raw_buf = self._raw_buf[read:]
            out_pos += written
            out_cap -= written

        return result, out_pos

    @property
    def raw(self: Self) -> io.RawIOBase:
        """Get the underlying raw stream."""
        return self._raw

    @property
    def closed(self: Self) -> bool:
        """Check if stream is closed."""
        return self.raw.closed

    @property
    def name(self: Self) -> str:
        """Get name."""
        return self.raw.name

    @property
    def mode(self: Self) -> str:
        """Get mode."""
        return self.raw.mode

    @property
    def job_stats(self: Self) -> JobStats:
        """Get job statistics."""
        return get_job_stats(self.__job)

    def __getstate__(self: Self) -> dict:
        """Pickle object."""
        msg = f"cannot pickle {self.__class__.__name__!r} object"
        raise TypeError(msg)

    def __setstate__(self: Self, obj: Any) -> dict:  # noqa: ANN401
        """Unpickle object."""
        msg = f"cannot unpickle {self.__class__.__name__!r} object"
        raise TypeError(msg)

    def __repr__(self: Self) -> str:
        """Repr the object."""
        modname = self.__class__.__module__
        clsname = self.__class__.__qualname__
        try:
            name = self.name
        except AttributeError:
            return f"<{modname}.{clsname}>"
        else:
            return f"<{modname}.{clsname} name={name!r}>"
