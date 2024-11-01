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
        self._raw_pos = 0
        self._buf = bytearray()
        self._pos = 0

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
        while result == RsResult.BLOCKED:
            with memoryview(c_buffer) as mv:
                result, written = self._chunk_readinto_unlocked(mv)
                chunks.append(mv[:written].tobytes())
                total_length += written
            if total_length >= size and size >=0:
                break

        self._buf = bytearray().join(chunks)

        if size < 0:
            size = len(self._buf)

        out = self._buf[:size]
        self._buf = self._buf[size:]
        return bytes(out)

    def _chunk_readinto_unlocked(self: Self, buf: memoryview) -> tuple[RsResult, int]:
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

    # def _read_unlocked(self: Self, n: int| None =None) -> bytes:
    #     nodata_val = b""
    #     empty_values = (b"", None)

    #     if n is None or n < 0:
    #         ...
    #         return b''

    #     if len(self._buf) > n:
    #         out = self._buf[:n]
    #         self._buf = self._buf[n:]
    #         return out

    #     buf_pos = len(self._buf)
    #     wanted = max(self.buffer_size - buf_pos, n)
    #     self._buf += bytearray(wanted)
    #     buf_len = len(self._buf)
    #     print(buf_pos)
    #     print(self._buf)
    #     print(buf_len)
    #     print(wanted)

    #     raw_wanted = max(wanted - len(self._raw_buf), 0)
    #     raw_buf_pos = 0

    #     result = RsResult.BLOCKED
    #     eof = False
    #     while result == RsResult.BLOCKED and buf_pos < buf_len:
    #         if not eof:
    #             raw_chunk = self.raw.read(raw_wanted)
    #             if raw_chunk in empty_values:
    #                 nodata_val = raw_chunk
    #                 eof = True
    #             else:
    #                 self._raw_buf += raw_chunk
    #         with memoryview(self._raw_buf) as ib, memoryview(self._buf) as ob:
    #             result, consumed, produced = job_iter(
    #                 self._job,
    #                 ib[raw_buf_pos:],
    #                 ob[buf_pos:],
    #                 eof=eof
    #             )
    #             buf_pos += produced
    #             raw_buf_pos += consumed

    #     self._raw_buf = self._raw_buf[raw_buf_pos:]

    #     out = self._buf[:buf_pos]
    #     self._buf = self._buf[buf_pos:]
    #     return bytes(out)

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


class Signature(io.BufferedReader):
    def __init__(
        self: Self,
        raw: io.RawIOBase,
        buffer_size: int = io.DEFAULT_BUFFER_SIZE,
        filesize: int = -1,
        signature_type: RsSignatureMagic = RsSignatureMagic.RK_BLAKE2_SIG,
        block_length: int = 0,
        hash_length: int = 0,
    ) -> None:
        super().__init__(raw, buffer_size)
        self._prev_input = bytes()
        self._job = sig_begin(
            filesize=filesize or -1,
            sig_magic=signature_type,
            block_length=block_length,
            hash_length=hash_length,
        )

    @property
    def stats(self: Self) -> JobStats:
        return get_job_stats(self._job)

    def seekable(self: Self) -> bool:
        return False

    def read(self: Self, size: int | None = -1, *args: Any, **kwargs: Any) -> bytes:
        if size is None:
            size = -1

        if size != 0:
            data = super().read(size, *args, **kwargs)
            print(f"eof={size < 0 or  len(data) < size}")
            return self._process_stream(data, size, size < 0 or len(data) < size)
        return b""

    def __del__(self):
        free_job(self._job)
        super().__del__()

    _in_buf = b""
    _out_buf = b""

    def _process_stream3(
        self: Self,
        input_: bytes,
        max_size: int,
        eof: bool,
    ):
        result = RsResult.BLOCKED
        self._in_buf += input_

        if max_size >= 0:
            input_ = self._in_buf[:max_size]
            self._in_buf = self._in_buf[max_size:]
        else:
            input_ = self._in_buf
            self._in_buf = b""

        while result == RsResult.BLOCKED and (
            max_size < 0 or (len(self._out_buf) < max_size and (input_ or eof))
        ):
            print(input_, not input_ and eof)
            result, input_, output = job_iter(
                self._job,
                input_,
                max_output_size=max(100, max_size, len(input_)),
                eof=(not input_ and eof),
            )
            self._out_buf += output

        if max_size >= 0:
            output = self._out_buf[:max_size]
            self._out_buf = self._out_buf[max_size:]
        else:
            output = self._out_buf
            self._out_buf = b""

        return output

    def _process_stream2(
        self,
        data: bytes,
        max_outptut_size: int,
    ) -> bytes:
        final_output = b""
        result = RsResult.BLOCKED

        data = self._prev_input + data
        if max_outptut_size >= 0:
            self._prev_input = data[max_outptut_size:]
            data = data[:max_outptut_size]

        while result == RsResult.BLOCKED and (
            len(final_output) < max_outptut_size or max_outptut_size < 0
        ):
            result, unprocessed_input, output = job_iter(
                self._job,
                data,
                eof=(
                    (max_outptut_size >= 0 and len(data) == 0) or max_outptut_size < 0
                ),
            )

            final_output += output
            self._prev_input += unprocessed_input

            if max_outptut_size >= 0:
                data = self._prev_input[: max_outptut_size - len(final_output)]
                self._prev_input = self._prev_input[
                    max_outptut_size - len(final_output) :
                ]

        return final_output

    def _process_stream1(
        self, data: bytes, max_outptut_size: int, *, eof: bool = False
    ) -> bytes:
        final_output = b""
        result = RsResult.BLOCKED

        if max_outptut_size < 0:
            next_chunk = self._prev_input + data
            self._prev_input = b""
        elif max_outptut_size < len(self._prev_input):
            next_chunk = self._prev_input[:max_outptut_size]
            self._prev_input = self._prev_input[max_outptut_size:] + data
        else:
            next_chunk = self._prev_input + data[:max_outptut_size]
            self._prev_input = data[max_outptut_size:]

        while result == RsResult.BLOCKED and (
            len(final_output) < max_outptut_size or max_outptut_size < 0
        ):
            result, unprocessed_input, output = job_iter(
                self._job,
                next_chunk,
                # Ensure there is enough space for the output
                max_output_size=max(self.stats.block_len, len(next_chunk)),
                eof=eof and (len(next_chunk) == 0),
            )
            final_output += output
            self._prev_input += unprocessed_input
            if 0 < max_outptut_size < len(final_output):
                next_chunk = self._prev_input[: max_outptut_size - len(final_output)]
                self._prev_input = self._prev_input[
                    max_outptut_size - len(final_output) :
                ]
            else:
                next_chunk = self._prev_input
                self._prev_input = b""

        return final_output


class Signature1:
    def __init__(
        self: Self,
        filesize: int | None = None,
        *,
        signature: RsSignatureMagic = RsSignatureMagic.RK_BLAKE2_SIG,
        block_length: int = 0,
        hash_length: int = 0,
    ) -> None:
        self._left_input = bytes()
        self._job = sig_begin(
            filesize=filesize or -1,
            sig_magic=signature,
            block_length=block_length,
            hash_length=hash_length,
        )

    @property
    def stats(self) -> JobStats:
        return get_job_stats(self._job)

    def __del__(self):
        free_job(self._job)

    def add(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            err = f"Expected instance of bytes, got id={type(data)}"
            ValueError(err)
        _, self._left_input, output = job_iter(
            self._job,
            self._left_input + data,
            # Ensure there is enough space for the output
            max_output_size=max(get_job_stats(self._job).block_len, len(data)),
            eof=False,
        )
        return output

    def complete(self) -> bytes:
        final_output = bytes()
        result = RsResult.BLOCKED
        while result == RsResult.BLOCKED:
            result, self._left_input, output = job_iter(
                self._job,
                self._left_input,
                # Ensure there is enough space for the output
                max_output_size=max(
                    get_job_stats(self._job).block_len, len(self._left_input)
                ),
                eof=True,
            )
            final_output += output
        return final_output
