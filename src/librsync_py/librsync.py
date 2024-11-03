# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync stream API."""

from __future__ import annotations

import io
import weakref
from threading import Lock
from typing import TYPE_CHECKING

from librsync_py import RsResult, RsSignatureMagic
from librsync_py._internals.wrappers import (
    JobStats,
    MatchStats,
    build_hash_table,
    delta_begin,
    free_job,
    free_sig,
    get_job_stats,
    get_match_stats,
    job_iter,
    loadsig_begin,
    sig_begin,
)

if TYPE_CHECKING:  # pragma: no cover
    from array import array
    from sys import version_info
    from typing import Any

    if version_info < (3, 11):  # pragma: no cover
        from typing_extensions import Self
    else:  # pragma: no cover
        from typing import Self

    from cffi.backend_ctypes import CTypesData  # type: ignore[import-untyped]


class Job(io.BufferedIOBase):
    """Librsync job wrapper.

    Accepts a librsync job, allocated with `sig_begin`, `loadsig_begin`,
    `delta_begin` or `patch_begin`. The job will be automatically deallocated
    with `free_job` when this object is garbage collected.
    """

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

        # Ensure proper deallocation happens when interpreter is shutting down
        weakref.finalize(self, self.__del__)

    def readable(self: Self) -> bool:
        """Check if the stream is readable."""
        self._checkClosed()
        self._check_c_api_freed()
        return self.raw.readable()

    def read(self: Self, size: int | None = -1) -> bytes:
        """Read up to size bytes."""
        self._checkClosed()
        self._check_c_api_freed()
        with self._read_lock:
            return self._read_unlocked(size, read1=False)

    def read1(self: Self, size: int | None = -1) -> bytes:
        """Read up to size bytes while performing at most 1 read() system call."""
        self._checkClosed()
        self._check_c_api_freed()
        with self._read_lock:
            return self._read_unlocked(size, read1=True)

    def readinto(self: Self, buffer: bytearray | memoryview | array) -> int:
        """Read up to size bytes into a buffer.

        :param buffer: The buffer to store the read data into
        :type buffer: Union[bytearray, memoryview, array]
        :returns: The size of the read data in bytes
        :rtype: int
        """
        self._checkClosed()
        self._check_c_api_freed()
        if not isinstance(buffer, memoryview):
            buffer = memoryview(buffer)
        if buffer.readonly:
            msg = '"buffer" must be writable'
            raise ValueError(msg)
        buffer = buffer.cast("B")

        with self._read_lock:
            _, length = self._readinto_unlocked(buffer, read1=False)
            return length

    def readinto1(self: Self, buffer: bytearray | memoryview | array) -> int:
        """Read up to size bytes into a buffer while performing at most 1 read() system call.

        :param buffer: The buffer to store the read data into
        :type buffer: Union[bytearray, memoryview, array]
        :returns: The size of the read data in bytes
        :rtype: int
        """
        self._checkClosed()
        self._check_c_api_freed()
        if not isinstance(buffer, memoryview):
            buffer = memoryview(buffer)
        if buffer.readonly:
            msg = '"buffer" must be writable'
            raise ValueError(msg)
        buffer = buffer.cast("B")

        with self._read_lock:
            _, length = self._readinto_unlocked(buffer, read1=True)
            return length

    def close(self: Self) -> None:
        """Close stream."""
        self._free_c_api_resources()
        if self.raw is not None and not self.closed:
            self.raw.close()

    def detach(self: Self) -> io.RawIOBase:
        """Detach from the underlying stream and return it."""
        if self.raw is None:
            msg = "raw stream already detached"
            raise ValueError(msg)
        raw = self._raw
        self._raw = None
        self._free_c_api_resources()
        return raw

    def _read_unlocked(
        self: Self,
        size: int | None = -1,
        *,
        read1: bool = False,
    ) -> bytes:
        """Read from the stream, without thread safety.

        :param size: The maximum amount of bytes to read.
        :type size: Optional[int]
        :returns: The read data.
        :rtype: bytes
        :param read1: Perform at most 1 read() system call.
        :type read1: bool
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
                result, written = self._readinto_unlocked(mv, read1=read1)
                chunks.append(mv[:written].tobytes())
                total_length += written
                if (total_length >= size and size >= 0) or read1:
                    break

        self._buf = bytearray().join(chunks)

        if size < 0:
            size = len(self._buf)

        out = self._buf[:size]
        self._buf = self._buf[size:]
        return bytes(out)

    def _readinto_unlocked(
        self: Self,
        buf: memoryview,
        *,
        read1: bool = False,
    ) -> tuple[RsResult, int]:
        """Read from the stream into a buffer, without thread safety.

        :param buf: The buffer to store the read data into.
        :type buf: memoryview
        :returns: The result of the operation and the bytes written to the buffer.
        :rtype: tuple[RsResult, int]
        :param read1: Perform at most 1 read() system call.
        :type read1: bool
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

            if read1:
                break

        return result, out_pos

    def _free_c_api_resources(self: Self) -> None:
        """Deallocate C API resources."""
        if self.__job:
            free_job(self.__job)
            self.__job = None

    def _check_c_api_freed(self: Self) -> None:
        """Raise ValueError if the C API resources have been freed."""
        if not self.__job:
            msg = "I/O operation on a freed librsync job"
            raise ValueError(msg)

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

    def __del__(self) -> None:
        """Deallocate the object."""
        self.close()
        self._free_c_api_resources()
        return super().__del__()

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


class Signature(Job):
    """Generate a new signature.

    Creates a new buffered reader object, similar to :class:`io.BufferedReader`,
    which can be read to get the signature data. Note however, that this
    object is not seekable.

    :param raw: The source stream
    :type raw: io.RawIOBase
    :param buffer_size: The size of the cache buffer in bytes. For files above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type buffer_size: int
    :file_size: The size of the file-like object represented by the raw stream.
    Set to `None` if unknown
    :type file_size: int
    :param block_length: The signature block length. Larger values make a
    shorter signature but increase the delta file size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :type hash_length: int
    """

    def __init__(  # noqa: PLR0913
        self: Self,
        raw: io.RawIOBase,
        buffer_size: int = io.DEFAULT_BUFFER_SIZE,
        file_size: int | None = None,
        sig_magic: RsSignatureMagic = RsSignatureMagic.RK_BLAKE2_SIG,
        block_length: int = 0,
        hash_length: int = 0,
    ) -> None:
        """Create the object."""
        super().__init__(
            sig_begin(
                filesize=file_size or -1,
                sig_magic=sig_magic,
                block_length=block_length,
                hash_length=hash_length,
            ),
            raw=raw,
            buffer_size=buffer_size,
        )


class Delta(Job):
    """Generate a new delta.

    Creates a new buffered reader object, similar to :class:`io.BufferedReader`,
    which can be read to get the delta. Note however, that this object is not
    seekable.

    :param sig_raw: The source signature stream
    :type sig_raw: io.RawIOBase
    :param basis_raw: The source basis stream
    :type basis_raw: io.RawIOBase
    :param buffer_size: The size of the cache buffer in bytes. For files above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type buffer_size: int
    """

    def __init__(
        self: Self,
        sig_raw: io.RawIOBase,
        basis_raw: io.RawIOBase,
        buffer_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> None:
        """Create the object."""
        self._raw_sig = sig_raw
        self.__sig_loaded = False
        self.__sig, self.__sig_job = loadsig_begin()
        super().__init__(
            job=delta_begin(self.__sig),
            raw=basis_raw,
            buffer_size=buffer_size,
        )

    def load_signature(self: Self) -> None:
        """Load the signature for creating the delta from the signature stream."""
        if not self.signature_loaded:
            self._check_signature_closed()
            self._check_signature_job_c_api_freed()
            self._check_signature_c_api_freed()
            with self._read_lock:
                self._load_signature_unlocked()

    def read(self: Self, size: int | None = -1) -> bytes:  # noqa: D102
        self._check_signature_loaded()
        return super().read(size)

    def read1(self: Self, size: int | None = -1) -> bytes:  # noqa: D102
        self._check_signature_loaded()
        return super().read1(size)

    def readinto(self: Self, buffer: bytearray | memoryview | array) -> int:  # noqa: D102
        self._check_signature_loaded()
        return super().readinto(buffer)

    def readinto1(self: Self, buffer: bytearray | memoryview | array) -> int:  # noqa: D102
        self._check_signature_loaded()
        return super().readinto1(buffer)

    def detach(self: Self) -> io.RawIOBase:  # noqa: D102
        self._free_signature_c_api_resources()
        return super().detach()

    def close(self: Self) -> None:  # noqa: D102
        self._free_signature_c_api_resources()
        return super().close()

    def close_signature(self: Self) -> None:
        """Close signature stream."""
        self._free_signature_job_c_api_resources()
        if self.raw_signature is not None and not self.signature_closed:
            self.raw_signature.close()

    def detach_signature(self: Self) -> io.RawIOBase:
        """Detach from the underlying signature stream and return it."""
        if self.raw_signature is None:
            msg = "raw_signature stream already detached"
            raise ValueError(msg)
        raw_signature = self._raw_sig
        self._raw_sig = None
        self._free_signature_job_c_api_resources()
        return raw_signature

    def _load_signature_unlocked(self: Self) -> None:
        """Load the signature for creating the delta from the signature stream."""
        if self.__sig_loaded:
            return

        input_ = b""
        output = bytearray()  # loading signatures produces no output
        chunk_size = max(self.buffer_size, 1)
        result = RsResult.BLOCKED
        with memoryview(output) as out_mv:
            while result == RsResult.BLOCKED:
                input_ += self._raw_sig.read(chunk_size)
                with memoryview(input_) as in_mv:
                    result, read, _ = job_iter(
                        self.__sig_job,
                        in_mv,
                        out_mv,
                        eof=len(in_mv) == 0,
                    )
                if read == 0 and len(input_):
                    msg = (
                        "Infinite loop detected. "
                        "Signature load job consumes no input but does not complete."
                    )
                    raise RuntimeError(msg)
                input_ = input_[read:]

        if result == RsResult.DONE:
            build_hash_table(self.__sig)  # Index the signature
            self.__sig_loaded = True
            self.close_signature()
            self._free_signature_job_c_api_resources()

    def _check_signature_loaded(self: Self) -> bool:
        """Raise ValueError if the signature stream is closed."""
        if not self.signature_loaded:
            msg = "Signature not loaded. Did you forget to call `.load_signature()`?"
            raise ValueError(msg)
        self._check_signature_c_api_freed()

    @property
    def signature_loaded(self: Self) -> bool:
        """Check the signature has been loaded. True after :meth:`load_signature()` is called."""
        return self.__sig_loaded

    @property
    def raw_signature(self: Self) -> io.RawIOBase:
        """Get the underlying raw signature stream."""
        return self._raw_sig

    @property
    def signature_closed(self: Self) -> bool:
        """Check if signature stream is closed."""
        return self.raw_signature.closed

    @property
    def match_stats(self: Self) -> MatchStats:
        """Get delta match statistics."""
        return get_match_stats(self.__sig)

    def _check_signature_closed(self: Self) -> None:
        """Raise a ValueError if signature file is closed."""
        if self.signature_closed:
            msg = "I/O operation on closed file."
            raise ValueError(msg)

    def _free_signature_c_api_resources(self: Self) -> None:
        """Deallocate signature C API resources."""
        if self.__sig:
            free_sig(self.__sig)
            self.__sig = None

    def _free_signature_job_c_api_resources(self: Self) -> None:
        """Deallocate signature job C API resources."""
        if self.__sig_job:
            free_job(self.__sig_job)
            self.__sig_job = None

    def _check_signature_c_api_freed(self: Self) -> None:
        """Raise ValueError if the signature C API resources have been freed."""
        if not self.__sig:
            msg = "I/O operation on a freed librsync signature"
            raise ValueError(msg)

    def _check_signature_job_c_api_freed(self: Self) -> None:
        """Raise ValueError if the signature job C API resources have been freed."""
        if not self.__sig_job:
            msg = "I/O operation on a freed librsync job"
            raise ValueError(msg)

    def __del__(self: Self) -> None:
        """Deallocate the object."""
        self.close_signature()
        self._free_signature_c_api_resources()
        self._free_signature_job_c_api_resources()
        return super().__del__()
