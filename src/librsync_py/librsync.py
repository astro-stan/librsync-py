# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html

from __future__ import annotations

import io
from sys import version_info
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, cast

from librsync_py import RsResult, RsSignatureMagic
from librsync_py._internals.wrappers import (JobStats, free_job, get_job_stats,
                                             job_iter, sig_begin)

if version_info < (3, 11):  # pragma: no cover
    from typing_extensions import Self
else:  # pragma: no cover
    from typing import Self

if TYPE_CHECKING:  # pragma: no cover
    from types import TracebackType

    from cffi.backend_ctypes import CTypesData  # type: ignore[import-untyped]


class Job(io.BufferedIOBase):
    def __init__(
        self, job: CTypesData, raw: io.RawIOBase, buffer_size=io.DEFAULT_BUFFER_SIZE
    ):
        """Create a new buffered reader using the given readable raw IO object."""
        if not raw.readable():
            raise OSError('"raw" argument must be readable.')

        self._raw = raw
        self._job = job

        if buffer_size <= 0:
            raise ValueError("invalid buffer size")
        self.buffer_size = buffer_size

        self._reset_bufs()
        self._read_lock = Lock()

    def readable(self: Self) -> bool:
        return self.raw.readable()

    def read(self: Self, size: int | None = -1) -> bytes:
        return self._read_unlocked(size)

    def close(self):
        if self.raw is not None and not self.closed:
            self.raw.close()

    def detach(self):
        if self.raw is None:
            raise ValueError("raw stream already detached")
        raw = self._raw
        self._raw = None
        return raw

    def _reset_bufs(self):
        self._raw_buf = b""
        self._buf = bytearray()

    def _read_unlocked(self: Self, size: int | None = -1):
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
        out_pos = 0
        out_cap = len(buf)

        result = RsResult.BLOCKED
        while result == RsResult.BLOCKED and out_cap > 0:
            self._raw_buf += self.raw.read(max(out_cap - len(self._raw_buf), 0))
            cap = len(self._raw_buf)

            with memoryview(self._raw_buf) as ib:
                result, read, written = job_iter(
                    self._job,
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
        return self._raw

    @property
    def closed(self):
        return self.raw.closed

    @property
    def name(self):
        return self.raw.name

    @property
    def mode(self):
        return self.raw.mode

    @property
    def job_stats(self: Self) -> JobStats:
        return get_job_stats(self._job)

    def __getstate__(self):
        raise TypeError(f"cannot pickle {self.__class__.__name__!r} object")

    def __repr__(self):
        modname = self.__class__.__module__
        clsname = self.__class__.__qualname__
        try:
            name = self.name
        except AttributeError:
            return "<{}.{}>".format(modname, clsname)
        else:
            return "<{}.{} name={!r}>".format(modname, clsname, name)
