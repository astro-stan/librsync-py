# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Tests for the stream API."""

from __future__ import annotations

import io
import re
from datetime import datetime
from time import sleep

import pytest

from librsync_py import Delta, JobStats, Patch, RsSignatureMagic, Signature
from librsync_py._internals import _lib


def _get_signature(
    basis: bytes | int | None = None,
    buffer_size: int = io.DEFAULT_BUFFER_SIZE,
) -> Signature:
    """Get a signature object.

    :param basis: The signature basis. None for `b"0" * 10 * buffer_size`, int for `b"0" * data`
    :type basis: Optional[bytes | int]
    :param buffer_size: The buffer size
    :type buffer_size: int
    :returns: The signature object
    :rtype: Signature
    """
    if isinstance(basis, int):
        basis = b"0" * basis

    return Signature(io.BytesIO(basis or b"0" * 10 * buffer_size), buffer_size)


def _get_delta(
    signature: Signature | None = None,
    basis: bytes | int | None = None,
    buffer_size: int = io.DEFAULT_BUFFER_SIZE,
) -> Delta:
    """Get a delta object.

    :param signature: The signature object. None for `_get_signature(buffer_size=buffer_size)`
    :type signature: Optional[Signature]
    :param basis: The delta basis. None for `b"0" * 10 * buffer_size`, int for  `b"0" * basis`
    :type basis: Optional[bytes]
    :param buffer_size: The buffer size
    :type buffer_size: int
    :returns: The delta object
    :rtype: Delta"""
    if isinstance(basis, int):
        basis = b"0" * basis
    # Read the signature and wrap it into BytesIO to make it seekable
    return Delta(
        io.BytesIO(
            signature.read()
            if signature
            else _get_signature(buffer_size=buffer_size).read()
        ),
        io.BytesIO(basis or b"0" * 10 * buffer_size),
        buffer_size,
    )


def _get_patch(
    basis: bytes | int | None = None,
    delta: Delta | None = None,
    buffer_size: int = io.DEFAULT_BUFFER_SIZE,
) -> Patch:
    """Get a patch object.

    :param basis: The patch basis. None for `b"0" * 10 * buffer_size`
    :type basis: Optional[bytes]
    :param basis: The delta basis. None for `b"0" * 10 * buffer_size`, int for  `b"0" * basis`
    :type delta: Optional[Delta]
    :param buffer_size: The buffer size
    :type buffer_size: int
    :returns: The delta object
    :rtype: Delta"""
    if isinstance(basis, int):
        basis = b"0" * basis
    if delta is None:
        delta = _get_delta(buffer_size=buffer_size)
    delta.load_signature()
    # Read the delta and wrap it into BytesIO to make it seekable
    return Patch(
        io.BytesIO(basis or b"0" * 10 * buffer_size),
        io.BytesIO(delta.read()),
        buffer_size,
    )


class _NotReadableStream(io.BytesIO):
    def readable(self) -> bool:
        return False


class _NotSeekableStream(io.BytesIO):
    def seekable(self) -> bool:
        return False


def test_signature_init_fails() -> None:
    """Test initialising a signature with invalid values."""
    with pytest.raises(OSError, match=r'"raw" argument must be readable.'):
        Signature(_NotReadableStream(b""))

    with pytest.raises(ValueError, match=r"invalid buffer size"):
        Signature(io.BytesIO(b""), 0)

    with pytest.raises(ValueError, match=r"invalid buffer size"):
        Signature(io.BytesIO(b""), buffer_size=-1)

    with pytest.raises(ValueError, match=r"Filesize must be >= 0"):
        Signature(io.BytesIO(b""), file_size=-2)  # -1 is valid, means "unknown"

    with pytest.raises(ValueError, match=r"Signature block length must be >0"):
        Signature(io.BytesIO(b""), block_length=-1)  # 0 is valid, means "recommended"

    with pytest.raises(ValueError, match=r"Invalid signature magic."):
        Signature(io.BytesIO(b""), sig_magic=1)  # 0 is valid, means "recommended"

    with pytest.raises(ValueError, match=r"Signature hash length must be >=-1"):
        # -1 and 0 are valid. Mean "minimum" and "maximum" respectively
        Signature(io.BytesIO(b""), hash_length=-2)

    with pytest.raises(ValueError, match=r"Signature hash length must be <=32"):
        # -1 and 0 are valid. Mean "minimum" and "maximum" respectively
        Signature(io.BytesIO(b""), hash_length=33)

    with pytest.raises(ValueError, match=r"Signature hash length must be <=16"):
        # -1 and 0 are valid. Mean "minimum" and "maximum" respectively
        Signature(io.BytesIO(b""), sig_magic=RsSignatureMagic.MD4_SIG, hash_length=17)


def test_delta_init_fails() -> None:
    """Test initialising a delta with invalid values."""
    with pytest.raises(OSError, match=r'"raw" argument must be readable.'):
        Delta(io.BytesIO(b""), _NotReadableStream(b""))

    with pytest.raises(OSError, match=r'"sig_raw" argument must be readable.'):
        Delta(_NotReadableStream(b""), io.BytesIO(b""))

    with pytest.raises(OSError, match=r'"sig_raw" argument must be readable.'):
        Delta(_NotReadableStream(b""), _NotReadableStream(b""))

    with pytest.raises(ValueError, match=r"invalid buffer size"):
        Delta(io.BytesIO(b""), io.BytesIO(b""), buffer_size=0)


def test_patch_init_fails() -> None:
    """Test initialising a patch with invalid values."""
    with pytest.raises(
        OSError, match=r"Expected a file-like object that is open for reading."
    ):
        Patch(_NotReadableStream(b""), io.BytesIO(b""))

    with pytest.raises(
        OSError,
        match=re.escape(
            r"Expected a file-like object which supports random access (.seek())."
        ),
    ):
        Patch(_NotSeekableStream(b""), io.BytesIO(b""))

    with pytest.raises(OSError, match=r'"raw" argument must be readable.'):
        Patch(io.BytesIO(b""), _NotReadableStream(b""))

    with pytest.raises(
        OSError, match=r"Expected a file-like object that is open for reading."
    ):
        Patch(_NotReadableStream(b""), _NotReadableStream(b""))

    with pytest.raises(
        OSError,
        match=re.escape(
            r"Expected a file-like object which supports random access (.seek())."
        ),
    ):
        Patch(_NotSeekableStream(b""), _NotReadableStream(b""))

    with pytest.raises(ValueError, match=r"invalid buffer size"):
        Patch(io.BytesIO(b""), io.BytesIO(b""), buffer_size=0)


def test_signature_init_args() -> None:
    """Test signature init args are applied."""
    stream = io.BytesIO(b"")
    s = Signature(stream)
    # The librsync sig_begin args are directly passed to the C API and
    # out of the scope of this test.
    assert s._job is not None  # noqa: SLF001
    assert s.buffer_size == io.DEFAULT_BUFFER_SIZE
    assert s.raw is stream

    # Test the signature magic is prepended by librsync
    assert (
        Signature(io.BytesIO(b""))
        .read()
        .startswith(RsSignatureMagic.RK_BLAKE2_SIG.to_bytes(4, byteorder="big"))
    )

    assert (
        Signature(io.BytesIO(b""), sig_magic=RsSignatureMagic.BLAKE2_SIG)
        .read()
        .startswith(RsSignatureMagic.BLAKE2_SIG.to_bytes(4, byteorder="big"))
    )

    assert (
        Signature(io.BytesIO(b""), sig_magic=RsSignatureMagic.RK_MD4_SIG)
        .read()
        .startswith(RsSignatureMagic.RK_MD4_SIG.to_bytes(4, byteorder="big"))
    )

    assert (
        Signature(io.BytesIO(b""), sig_magic=RsSignatureMagic.MD4_SIG)
        .read()
        .startswith(RsSignatureMagic.MD4_SIG.to_bytes(4, byteorder="big"))
    )


def test_delta_init_args() -> None:
    """Test delta init args are applied."""
    sig_stream = io.BytesIO(b"")
    basis_stream = io.BytesIO(b"")
    d = Delta(sig_stream, basis_stream)
    # Job should not be created until the signature is loaded
    assert d._job is None  # noqa: SLF001
    assert d._sig_job is not None  # noqa: SLF001
    assert d._sig is not None  # noqa: SLF001
    assert d.raw_signature is sig_stream
    assert d.raw is basis_stream
    assert d.buffer_size == io.DEFAULT_BUFFER_SIZE


def test_patch_init_args() -> None:
    """Test patch init args are applied."""
    basis_stream = io.BytesIO(b"")
    delta_stream = io.BytesIO(b"")
    p = Patch(basis_stream, delta_stream)
    assert p._job is not None  # noqa: SLF001
    assert p.buffer_size == io.DEFAULT_BUFFER_SIZE
    assert p.raw is delta_stream
    assert p.raw_basis is basis_stream


def test_delta_load_signature() -> None:
    """Test loading a signature stream."""
    buffer_size = 10
    data_size = 10 * buffer_size
    obj = _get_delta(basis=data_size, buffer_size=buffer_size)

    res = obj.load_signature(0)
    assert isinstance(res, int) and res == 0
    res = obj.load_signature1(0)
    assert isinstance(res, int) and res == 0
    res = obj.load_signature(1)
    assert isinstance(res, int) and res == 1
    res = obj.load_signature1(2)
    assert isinstance(res, int) and res == 2
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = _get_delta(basis=data_size, buffer_size=buffer_size)
        res = obj.load_signature1(arg)
        assert isinstance(res, int) and res == buffer_size
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = _get_delta(basis=data_size, buffer_size=buffer_size)
        res = obj.load_signature(arg)
        assert isinstance(res, int) and res > 0
        res = obj.load_signature(arg)
        assert isinstance(res, int) and res == 0


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_read(cls: type[Signature | Delta | Patch]) -> None:
    """Test reading a processed stream."""
    buffer_size = 10
    data_size = 10 * buffer_size

    if cls is Signature:
        get_obj = lambda: _get_signature(basis=data_size, buffer_size=buffer_size)
    elif cls is Delta:

        def get_obj() -> Delta:
            o = _get_delta(basis=data_size, buffer_size=buffer_size)
            o.load_signature()
            return o
    else:
        get_obj = lambda: _get_patch(basis=data_size, buffer_size=buffer_size)

    obj = get_obj()
    assert obj.readable()

    res = obj.read(0)
    assert isinstance(res, bytes) and len(res) == 0
    res = obj.read1(0)
    assert isinstance(res, bytes) and len(res) == 0
    res = obj.read(1)
    assert isinstance(res, bytes) and len(res) == 1
    res = obj.read1(2)
    assert isinstance(res, bytes) and len(res) == 2
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = get_obj()
        res = obj.read1(arg)
        assert isinstance(res, bytes) and 0 < len(res) <= buffer_size
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = get_obj()
        res = obj.read(arg)
        assert isinstance(res, bytes) and len(res) > 0
        res = obj.read(arg)
        assert isinstance(res, bytes) and len(res) == 0


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_readinto(cls: type[Signature | Delta | Patch]) -> None:
    """Test reading a processed stream into a buffer."""
    buffer_size = 10
    data_size = 10 * buffer_size

    if cls is Signature:
        get_obj = lambda: _get_signature(basis=data_size, buffer_size=buffer_size)
    elif cls is Delta:

        def get_obj() -> Delta:
            o = _get_delta(basis=data_size, buffer_size=buffer_size)
            o.load_signature()
            return o
    else:
        get_obj = lambda: _get_patch(basis=data_size, buffer_size=buffer_size)

    obj = get_obj()
    assert obj.readable()

    buffer = bytearray()

    res = obj.readinto(buffer)
    assert isinstance(res, int) and res == 0
    res = obj.readinto1(buffer)
    assert isinstance(res, int) and res == 0
    res = obj.readinto(memoryview(buffer))
    assert isinstance(res, int) and res == 0
    res = obj.readinto1(memoryview(buffer))
    assert isinstance(res, int) and res == 0

    buffer = bytearray(1)

    res = obj.readinto(buffer)
    assert isinstance(res, int) and res == 1 and buffer != bytearray(1)
    res = obj.readinto(memoryview(buffer))
    assert isinstance(res, int) and res == 1 and buffer != bytearray(1)

    buffer = bytearray(3)

    res = obj.readinto1(buffer)
    assert isinstance(res, int) and res == 3 and buffer != bytearray(3)
    res = obj.readinto1(memoryview(buffer))
    assert isinstance(res, int) and res == 3 and buffer != bytearray(3)

    buffer = bytearray(data_size)

    obj = get_obj()
    res = obj.readinto1(buffer)
    assert isinstance(res, int) and res > 0
    assert buffer != bytearray(data_size)

    obj = get_obj()
    res = obj.readinto(buffer)
    assert isinstance(res, int) and res > 0
    assert buffer != bytearray(data_size)


def test_signature_close() -> None:
    """Test closing a signature stream."""
    obj = _get_signature()
    obj.close()
    assert obj.raw.closed
    assert obj.closed
    assert obj._job is None

    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.read()
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.read1()
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readinto(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readable()


def test_delta_close() -> None:
    """Test closing a delta stream."""
    obj = _get_delta()
    obj.load_signature()

    obj.close_signature()
    assert obj.raw_signature.closed
    assert obj.signature_closed
    assert not obj.closed
    assert obj._sig is not None
    assert obj._job is not None
    assert obj._sig_job is None

    obj.close()
    assert obj.raw.closed
    assert obj.signature_closed
    assert obj.closed
    assert obj._job is None
    assert obj._sig is None

    obj = _get_delta()
    obj.close_signature()
    assert obj.signature_closed
    assert not obj.closed

    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.load_signature()
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.load_signature1()

    obj = _get_delta()
    obj.close()
    assert not obj.signature_closed
    assert obj.closed

    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.load_signature()
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.load_signature1()

    obj = _get_delta()
    obj.load_signature()
    obj.close()
    assert not obj.signature_closed
    assert obj.closed

    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.read()
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.read1()
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.readinto(bytearray())
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readable()


def test_patch_close() -> None:
    """Test closing a patch stream."""
    obj = _get_patch()

    obj.close_basis()
    assert obj.raw_basis.closed
    assert obj.basis_closed
    assert not obj.closed
    assert obj._job is None

    obj.close()
    assert obj.raw.closed
    assert obj.basis_closed
    assert obj.closed
    assert obj._job is None

    obj = _get_patch()
    obj.close_basis()
    assert obj.basis_closed
    assert not obj.closed

    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read1()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readable()

    obj = _get_patch()
    obj.close()
    assert not obj.basis_closed
    assert obj.closed

    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.read()
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.read1()
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readinto(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on closed file."):
        obj.readable()


def test_signature_detach() -> None:
    """Test detaching a signature stream."""
    obj = _get_signature()
    obj.detach()
    assert obj.raw is None
    assert obj._job is None

    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read1()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readable()


def test_delta_detach() -> None:
    """Test detaching a delta stream."""
    obj = _get_delta()
    obj.load_signature()

    obj.detach_signature()
    assert obj.raw_signature is None
    assert obj.raw is not None
    assert obj._sig is not None
    assert obj._job is not None
    assert obj._sig_job is None

    obj.detach()
    assert obj.raw is None
    assert obj._job is None
    assert obj._sig is None

    obj = _get_delta()
    obj.detach_signature()
    assert obj.raw_signature is None
    assert obj.raw is not None

    with pytest.raises(AttributeError):
        obj.load_signature()
    with pytest.raises(AttributeError):
        obj.load_signature1()

    obj = _get_delta()
    obj.detach()
    assert obj.raw_signature is not None
    assert obj.raw is None

    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.load_signature()
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.load_signature1()

    obj = _get_delta()
    obj.load_signature()
    obj.detach()
    assert obj.raw_signature is not None
    assert obj.raw is None

    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.read()
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.read1()
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.readinto(bytearray())
    with pytest.raises(
        ValueError, match=r"I/O operation on a freed librsync signature."
    ):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readable()


def test_patch_detach() -> None:
    """Test detaching a patch stream."""
    obj = _get_patch()

    obj.detach_basis()
    assert obj.raw_basis is None
    assert obj.raw is not None
    assert obj._job is None

    obj.detach()
    assert obj.raw is None
    assert obj._job is None

    obj = _get_patch()
    obj.detach_basis()
    assert obj.raw_basis is None
    assert obj.raw is not None

    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read1()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readable()

    obj = _get_patch()
    obj.detach()
    assert obj.raw is None
    assert obj._job is None

    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.read1()
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readinto1(bytearray())
    with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
        obj.readable()


def test_signature_context_manager_api() -> None:
    """Test signature context manager API."""
    with _get_signature() as obj:
        assert not obj.closed
        assert obj._job is not None

    assert obj.closed
    assert obj._job is None


def test_delta_context_manager_api() -> None:
    """Test delta context manager API."""
    with _get_delta() as obj:
        assert not obj.closed
        assert not obj.signature_closed
        # job should not be created until signature is loaded
        assert obj._job is None
        assert obj._sig is not None
        assert obj._sig_job is not None

    with _get_delta() as obj:
        obj.load_signature()
        assert not obj.closed
        assert not obj.signature_closed
        assert obj._job is not None
        assert obj._sig is not None
        assert obj._sig_job is not None

    assert obj.closed
    assert obj.signature_closed
    assert obj._job is None
    assert obj._sig is None
    assert obj._sig_job is None


def test_patch_context_manager_api() -> None:
    """Test patch context manager API."""
    with _get_patch() as obj:
        assert not obj.closed
        assert not obj.basis_closed
        assert obj._job is not None

    assert obj.closed
    assert obj.basis_closed
    assert obj._job is None


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_job_stats(cls: type[Signature | Delta | Patch]) -> None:
    """Test job statistics."""

    if cls is Signature:
        obj = _get_signature()
        job_type = JobStats.JobType.SIGNATURE
    elif cls is Delta:
        obj = _get_delta()
        job_type = JobStats.JobType.DELTA
    else:
        obj = _get_patch()
        job_type = JobStats.JobType.PATCH

    # The start time is recorded by the C API, which in turn measures
    # epoch time, so it is limited to 1s intervals. Sleep for 1 second to
    # ensure the time taken is > 0
    sleep(1)

    # Delta job is not loaded until signature is loaded
    if cls is not Delta:
        assert isinstance(obj.job_stats, JobStats)
        assert obj.job_stats.job_type == job_type
        assert obj.job_stats.lit_cmds == 0
        assert obj.job_stats.lit_bytes == 0
        assert obj.job_stats.lit_cmdbytes == 0
        assert obj.job_stats.copy_cmds == 0
        assert obj.job_stats.copy_bytes == 0
        assert obj.job_stats.copy_cmdbytes == 0
        assert obj.job_stats.sig_cmds == 0
        assert obj.job_stats.sig_bytes == 0
        assert obj.job_stats.false_matches == 0
        assert obj.job_stats.sig_blocks == 0
        assert obj.job_stats.block_len == 0
        assert obj.job_stats.in_bytes == 0
        assert obj.job_stats.out_bytes == 0
        assert isinstance(obj.job_stats.start_time, datetime)
        assert obj.job_stats.completion_time is None
        # Time taken is measured as the difference between time now and start time
        # rounded down to the last full second
        assert obj.job_stats.time_taken == 1
        assert obj.job_stats.in_speed == 0
        assert obj.job_stats.out_speed == 0

    if cls is Delta:
        assert isinstance(obj.signature_job_stats, JobStats)
        assert obj.signature_job_stats.job_type == JobStats.JobType.LOAD_SIGNATURE
        assert obj.signature_job_stats.lit_cmds == 0
        assert obj.signature_job_stats.lit_bytes == 0
        assert obj.signature_job_stats.lit_cmdbytes == 0
        assert obj.signature_job_stats.copy_cmds == 0
        assert obj.signature_job_stats.copy_bytes == 0
        assert obj.signature_job_stats.copy_cmdbytes == 0
        assert obj.signature_job_stats.sig_cmds == 0
        assert obj.signature_job_stats.sig_bytes == 0
        assert obj.signature_job_stats.false_matches == 0
        assert obj.signature_job_stats.sig_blocks == 0
        assert obj.signature_job_stats.block_len == 0
        assert obj.signature_job_stats.in_bytes == 0
        assert obj.signature_job_stats.out_bytes == 0
        assert isinstance(obj.signature_job_stats.start_time, datetime)
        assert obj.signature_job_stats.completion_time is None
        # Time taken is measured as the difference between time now and start time
        # rounded down to the last full second
        assert obj.signature_job_stats.time_taken == 1
        assert obj.signature_job_stats.in_speed == 0
        assert obj.signature_job_stats.out_speed == 0

        obj.load_signature()

        raw_stats = _lib.rs_job_statistics(obj._sig_job)

        in_len = len(_get_delta().raw_signature.read())

        assert isinstance(obj.job_stats, JobStats)
        assert obj.signature_job_stats.job_type == JobStats.JobType.LOAD_SIGNATURE
        assert obj.signature_job_stats.lit_cmds == raw_stats.lit_cmds
        assert obj.signature_job_stats.lit_bytes == raw_stats.lit_bytes
        assert obj.signature_job_stats.lit_cmdbytes == raw_stats.lit_cmdbytes
        assert obj.signature_job_stats.copy_cmds == raw_stats.copy_cmds
        assert obj.signature_job_stats.copy_bytes == raw_stats.copy_bytes
        assert obj.signature_job_stats.copy_cmdbytes == raw_stats.copy_cmdbytes
        assert obj.signature_job_stats.sig_cmds == raw_stats.sig_cmds
        assert obj.signature_job_stats.sig_bytes == raw_stats.sig_bytes
        assert obj.signature_job_stats.false_matches == raw_stats.false_matches
        assert obj.signature_job_stats.sig_blocks == raw_stats.sig_blocks
        assert obj.signature_job_stats.block_len == raw_stats.block_len
        assert obj.signature_job_stats.in_bytes == in_len
        assert obj.signature_job_stats.out_bytes == 0
        assert isinstance(obj.signature_job_stats.start_time, datetime)
        assert isinstance(obj.signature_job_stats.completion_time, datetime)
        assert obj.signature_job_stats.time_taken == 1
        assert (
            obj.signature_job_stats.in_speed
            == in_len / obj.signature_job_stats.time_taken
        )
        assert obj.signature_job_stats.out_speed == 0

    # The completion time is recorded by the C API, which in turn measures
    # epoch time, so it is limited to 1s intervals. Sleep for 1 second to
    # ensure the time taken is > 1
    sleep(1)

    out_len = len(obj.read())
    if cls is Signature:
        in_len = len(_get_signature().raw.read())
    elif cls is Delta:
        in_len = len(_get_delta().raw.read())
    elif cls is Patch:
        delta = _get_delta()
        delta.load_signature()
        in_len = len(delta.read())

    raw_stats = _lib.rs_job_statistics(obj._job)

    assert isinstance(obj.job_stats, JobStats)
    assert obj.job_stats.job_type == job_type
    assert obj.job_stats.lit_cmds == raw_stats.lit_cmds
    assert obj.job_stats.lit_bytes == raw_stats.lit_bytes
    assert obj.job_stats.lit_cmdbytes == raw_stats.lit_cmdbytes
    assert obj.job_stats.copy_cmds == raw_stats.copy_cmds
    assert obj.job_stats.copy_bytes == raw_stats.copy_bytes
    assert obj.job_stats.copy_cmdbytes == raw_stats.copy_cmdbytes
    assert obj.job_stats.sig_cmds == raw_stats.sig_cmds
    assert obj.job_stats.sig_bytes == raw_stats.sig_bytes
    assert obj.job_stats.false_matches == raw_stats.false_matches
    assert obj.job_stats.sig_blocks == raw_stats.sig_blocks
    assert obj.job_stats.block_len == raw_stats.block_len
    assert obj.job_stats.in_bytes == in_len
    assert obj.job_stats.out_bytes == out_len
    assert isinstance(obj.job_stats.start_time, datetime)
    assert isinstance(obj.job_stats.completion_time, datetime)
    if cls is Delta:
        # Job doesn't get created until after signature is loaded
        assert obj.job_stats.time_taken == 1
    else:
        assert obj.job_stats.time_taken == 2
    assert obj.job_stats.in_speed == in_len / obj.job_stats.time_taken
    assert obj.job_stats.out_speed == out_len / obj.job_stats.time_taken

    obj.close()

    if cls is Delta:
        with pytest.raises(
            ValueError, match=r"I/O operation on a freed librsync signature."
        ):
            obj.job_stats
        obj.close_signature()
        with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
            obj.signature_job_stats
    else:
        with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
            obj.job_stats

def test_delta_match_stats() -> None:
    """Test delta job match statistics."""
    text_orig = bytearray(b"123" * 1024 * 100)
    text_new = text_orig

    text_orig = b"666" * 100 + text_orig
    text_new += b"999" * 123

    obj = _get_delta(Signature(io.BytesIO(text_orig)), text_new)

    with pytest.raises(ValueError, match=r"Invalid signature magic."):
        obj.match_stats

    obj.load_signature()

    assert obj.match_stats.find_count == 0
    assert obj.match_stats.match_count == 0
    assert obj.match_stats.hashcmp_count == 0
    assert obj.match_stats.entrycmp_count == 0
    assert obj.match_stats.strongsum_calc_count == 0
    assert obj.match_stats.weaksumcmp_count == 0
    assert obj.match_stats.strongsumcmp_count == 0
    assert obj.match_stats.weaksumcmp_ratio == 0
    assert obj.match_stats.entrycmp_ratio == 0
    assert obj.match_stats.strongsumcmp_ratio == 0
    assert obj.match_stats.match_ratio == 0
    assert obj.match_stats.strongsum_calc_ratio == 0

    obj.read()

    # Derefecene struct
    sig = obj._sig[0][0]

    assert obj.match_stats.find_count == sig.hashtable.find_count
    assert obj.match_stats.match_count == sig.hashtable.match_count
    assert obj.match_stats.hashcmp_count == sig.hashtable.hashcmp_count
    assert obj.match_stats.entrycmp_count == sig.hashtable.entrycmp_count
    assert obj.match_stats.strongsum_calc_count == sig.calc_strong_count
    assert obj.match_stats.weaksumcmp_count == obj.match_stats.hashcmp_count
    assert obj.match_stats.strongsumcmp_count == obj.match_stats.entrycmp_count
    assert (
        obj.match_stats.hashcmp_ratio
        == obj.match_stats.hashcmp_count / obj.match_stats.find_count
    )
    assert obj.match_stats.weaksumcmp_ratio == obj.match_stats.hashcmp_ratio
    assert (
        obj.match_stats.entrycmp_ratio
        == obj.match_stats.entrycmp_count / obj.match_stats.find_count
    )
    assert obj.match_stats.strongsumcmp_ratio == obj.match_stats.entrycmp_ratio
    assert (
        obj.match_stats.match_ratio
        == obj.match_stats.match_count / obj.match_stats.find_count
    )
    assert (
        obj.match_stats.strongsum_calc_ratio
        == obj.match_stats.strongsum_calc_count / obj.match_stats.find_count
    )

# @pytest.mark.parametrize("cls", [Signature, Delta, Patch])
# def test_reading(cls: type[Signature | Delta | Patch]) -> None:
#     """Test stream reading."""
#     buffer_size = 10
#     data_size = 10 * buffer_size

#     if cls is Signature:
#         get_obj = lambda: _get_signature(basis=data_size, buffer_size=buffer_size)
#     elif cls is Delta:
#         get_obj = lambda: _get_delta(basis=data_size, buffer_size=buffer_size)
#     else:
#         get_obj = lambda: _get_patch(basis=data_size, buffer_size=buffer_size)

#     obj = get_obj()

#     if cls is Delta:
#         assert obj.load_signature(0) == 0
#         assert obj.load_signature1(0) == 0
#         assert obj.load_signature(1) == 1
#         assert obj.load_signature1(2) == 2
#         assert obj.load_signature1() == buffer_size
#         # Check the buffer has been filled
#         assert len(obj._sig_buf) == 0
#         # load the rest of the signature
#         assert obj.load_signature() < data_size
#         # Check there isn't more to load
#         assert obj.load_signature() == 0

#         # < -1 is an edge case, which should be treated as being -1
#         for arg in (None, -1, -2):
#             obj = get_obj()
#             assert obj.load_signature(arg) <= data_size
#             assert obj.load_signature(arg) == 0
#             assert obj.load_signature1(arg) == 0


#     assert obj.readable()
#     assert obj.read(0) == b""
#     assert len(obj.read1(0)) == 0
#     assert len(obj.read(1)) == 1
#     assert len(obj.read1(2)) == 2
#     assert len(obj.read1()) == buffer_size
#     # Check the buffer has been filled
#     assert len(obj._sig_buf) == 0
#     # load the rest of the signature
#     assert len(obj.read()) < data_size
#     # Check there isn't more to load
#     assert len(obj.read()) == 0

#     # < -1 is an edge case, which should be treated as being -1
#     for arg in (None, -1, -2):
#         obj = get_obj()
#         assert len(obj.read(arg)) <= data_size
#         assert len(obj.read(arg)) == 0
#         assert len(obj.read1(arg)) == 0


def test_full() -> None:
    orig = ((b"123" * 256) + b"4") * 64
    new = ((b"123" * 256) + b"5") * 48

    buffer_size = 10

    sig = Signature(io.BytesIO(orig), buffer_size=buffer_size)
    sig_contents = bytearray()
    sig_contents += sig.read(1)
    sig_contents += sig.read1(1)
    sig_contents += sig.read(10)
    sig_contents += sig.read1(10)
    sig_contents += bytearray(100)
    sig.readinto(
        memoryview(sig_contents)[len(sig_contents) - 100 : len(sig_contents) - 10]
    )
    sig.readinto1(memoryview(sig_contents)[len(sig_contents) - 10 :])
    sig_contents += sig.read1(100)
    sig_contents += sig.read(100)
    sig_contents += sig.read1()
    sig_contents += sig.read()

    delta = Delta(io.BytesIO(sig_contents), io.BytesIO(new), buffer_size=buffer_size)
    delta.load_signature(10)
    delta.load_signature1(10)
    delta.load_signature(10)
    delta.load_signature(1)
    delta.load_signature1(11)
    delta.load_signature1()
    delta.load_signature()
    delta_contents = bytearray()
    delta_contents += delta.read(1)
    delta_contents += delta.read1(1)
    delta_contents += delta.read(10)
    delta_contents += delta.read1(10)
    delta_contents += bytearray(100)
    delta.readinto(
        memoryview(delta_contents)[len(delta_contents) - 100 : len(delta_contents) - 10]
    )
    delta.readinto1(memoryview(delta_contents)[len(delta_contents) - 10 :])
    delta_contents += delta.read1(100)
    delta_contents += delta.read(100)
    delta_contents += delta.read1()
    delta_contents += delta.read()

    patch = Patch(io.BytesIO(orig), io.BytesIO(delta_contents), buffer_size=buffer_size)
    patched_orig = bytearray()
    patched_orig += patch.read(1)
    patched_orig += patch.read1(1)
    patched_orig += patch.read(10)
    patched_orig += patch.read1(10)
    patched_orig += bytearray(100)
    patch.readinto(
        memoryview(patched_orig)[len(patched_orig) - 100 : len(patched_orig) - 10]
    )
    patch.readinto1(memoryview(patched_orig)[len(patched_orig) - 10 :])
    patched_orig += patch.read1(100)
    patched_orig += patch.read(100)
    patched_orig += patch.read1()
    patched_orig += patch.read()

    assert new == patched_orig
