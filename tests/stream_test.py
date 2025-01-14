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

from librsync_py import Delta, JobStatistics, JobType, Patch, Signature, SignatureType
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
    :rtype: Delta
    """
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
    :rtype: Delta
    """
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

    with pytest.raises(ValueError, match=r"Invalid signature type."):
        # signature_type=0 is valid, means "recommended"
        Signature(io.BytesIO(b""), signature_type=1)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"Signature hash length must be >=-1"):
        # -1 and 0 are valid. Mean "minimum" and "maximum" respectively
        Signature(io.BytesIO(b""), hash_length=-2)

    with pytest.raises(ValueError, match=r"Signature hash length must be <=32"):
        Signature(io.BytesIO(b""), hash_length=33)

    with pytest.raises(ValueError, match=r"Signature hash length must be <=16"):
        Signature(io.BytesIO(b""), signature_type=SignatureType.MD4, hash_length=17)


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

    # Test the signature type is prepended by librsync
    assert (
        Signature(io.BytesIO(b""))
        .read()
        .startswith(SignatureType.RK_BLAKE2.to_bytes(4, byteorder="big"))
    )

    assert (
        Signature(io.BytesIO(b""), signature_type=SignatureType.BLAKE2)
        .read()
        .startswith(SignatureType.BLAKE2.to_bytes(4, byteorder="big"))
    )

    assert (
        Signature(io.BytesIO(b""), signature_type=SignatureType.RK_MD4)
        .read()
        .startswith(SignatureType.RK_MD4.to_bytes(4, byteorder="big"))
    )

    assert (
        Signature(io.BytesIO(b""), signature_type=SignatureType.MD4)
        .read()
        .startswith(SignatureType.MD4.to_bytes(4, byteorder="big"))
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


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_pickling_not_supported(cls: type[Signature | Delta | Patch]) -> None:
    """Test picking and unpickling the streams is not supported."""
    obj: Signature | Delta | Patch

    if cls is Signature:
        obj = _get_signature()
    elif cls is Delta:
        obj = _get_delta()
    else:
        obj = _get_patch()

    with pytest.raises(TypeError, match=r"Cannot pickle.*object"):
        obj.__getstate__()
    with pytest.raises(TypeError, match=r"Cannot unpickle.*object"):
        obj.__setstate__({})


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_repr(cls: type[Signature | Delta | Patch]) -> None:
    """Test picking and unpickling the streams is not supported."""
    obj: Signature | Delta | Patch

    if cls is Signature:
        obj = _get_signature()
    elif cls is Delta:
        obj = _get_delta()
    else:
        obj = _get_patch()

    assert len(f"{obj!r}") > 0


def test_delta_load_signature() -> None:
    """Test loading a signature stream."""
    buffer_size = 10
    data_size = 10 * buffer_size
    obj = _get_delta(basis=data_size, buffer_size=buffer_size)

    assert not obj.signature_loaded

    msg = r"Signature not loaded. Did you forget to call `.load_signature()`?"
    with pytest.raises(ValueError, match=msg):
        obj.read()
    with pytest.raises(ValueError, match=msg):
        obj.read1()
    with pytest.raises(ValueError, match=msg):
        obj.readinto(bytearray(100))
    with pytest.raises(ValueError, match=msg):
        obj.readinto1(bytearray(100))
    with pytest.raises(ValueError, match=msg):
        # Delta job is not created until the signature is fully loaded
        obj.job_stats  # noqa: B018

    res = obj.load_signature(0)
    assert isinstance(res, int)
    assert res == 0
    res = obj.load_signature1(0)
    assert isinstance(res, int)
    assert res == 0
    res = obj.load_signature(1)
    assert isinstance(res, int)
    assert res == 1
    res = obj.load_signature1(2)
    assert isinstance(res, int)
    assert res == 2  # noqa: PLR2004
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = _get_delta(basis=data_size, buffer_size=buffer_size)
        assert not obj.signature_loaded
        res = obj.load_signature(arg)
        assert isinstance(res, int)
        assert res > 0
        assert obj.signature_loaded

        res = obj.load_signature(arg)
        assert isinstance(res, int)
        assert res == 0
        assert obj.signature_loaded

    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = _get_delta(basis=data_size, buffer_size=buffer_size)
        assert not obj.signature_loaded
        res = obj.load_signature1(arg)
        assert isinstance(res, int)
        assert res == buffer_size

        obj.load_signature(arg)
        assert obj.signature_loaded

        res = obj.load_signature1(arg)
        assert isinstance(res, int)
        assert res == 0
        assert obj.signature_loaded


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_read(cls: type[Signature | Delta | Patch]) -> None:
    """Test reading a processed stream."""
    buffer_size = 10
    data_size = 10 * buffer_size

    if cls is Signature:

        def get_obj() -> Signature | Delta | Patch:
            return _get_signature(basis=data_size, buffer_size=buffer_size)
    elif cls is Delta:

        def get_obj() -> Signature | Delta | Patch:
            o = _get_delta(basis=data_size, buffer_size=buffer_size)
            o.load_signature()
            return o
    else:

        def get_obj() -> Signature | Delta | Patch:
            return _get_patch(basis=data_size, buffer_size=buffer_size)

    obj = get_obj()
    assert obj.readable()

    res = obj.read(0)
    assert isinstance(res, bytes)
    assert len(res) == 0
    res = obj.read1(0)
    assert isinstance(res, bytes)
    assert len(res) == 0
    res = obj.read(1)
    assert isinstance(res, bytes)
    assert len(res) == 1
    res = obj.read1(2)
    assert isinstance(res, bytes)
    assert len(res) == 2  # noqa: PLR2004
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = get_obj()
        res = obj.read1(arg)
        assert isinstance(res, bytes)
        assert 0 < len(res) <= buffer_size
    for arg in (None, -1, -2):  # < -1 should be treated as -1
        obj = get_obj()
        res = obj.read(arg)
        assert isinstance(res, bytes)
        assert len(res) > 0
        res = obj.read(arg)
        assert isinstance(res, bytes)
        assert len(res) == 0


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_readinto(cls: type[Signature | Delta | Patch]) -> None:  # noqa: PLR0915
    """Test reading a processed stream into a buffer."""
    buffer_size = 10
    data_size = 10 * buffer_size

    if cls is Signature:

        def get_obj() -> Signature | Delta | Patch:
            return _get_signature(basis=data_size, buffer_size=buffer_size)
    elif cls is Delta:

        def get_obj() -> Signature | Delta | Patch:
            o = _get_delta(basis=data_size, buffer_size=buffer_size)
            o.load_signature()
            return o
    else:

        def get_obj() -> Signature | Delta | Patch:
            return _get_patch(basis=data_size, buffer_size=buffer_size)

    obj = get_obj()
    assert obj.readable()

    msg = r'"buffer" must be writable'
    with pytest.raises(ValueError, match=msg):
        obj.readinto(b"")
    with pytest.raises(ValueError, match=msg):
        obj.readinto1(b"")

    buffer = bytearray()

    res = obj.readinto(buffer)
    assert isinstance(res, int)
    assert res == 0
    res = obj.readinto1(buffer)
    assert isinstance(res, int)
    assert res == 0
    res = obj.readinto(memoryview(buffer))
    assert isinstance(res, int)
    assert res == 0
    res = obj.readinto1(memoryview(buffer))
    assert isinstance(res, int)
    assert res == 0

    buffer = bytearray(1)

    res = obj.readinto(buffer)
    assert isinstance(res, int)
    assert res == 1
    assert buffer != bytearray(1)
    res = obj.readinto(memoryview(buffer))
    assert isinstance(res, int)
    assert res == 1
    assert buffer != bytearray(1)

    buffer = bytearray(3)

    res = obj.readinto1(buffer)
    assert isinstance(res, int)
    assert res == 3  # noqa: PLR2004
    assert buffer != bytearray(3)
    res = obj.readinto1(memoryview(buffer))
    assert isinstance(res, int)
    assert res == 3  # noqa: PLR2004
    assert buffer != bytearray(3)

    buffer = bytearray(data_size)

    obj = get_obj()
    res = obj.readinto1(buffer)
    assert isinstance(res, int)
    assert res > 0
    assert buffer != bytearray(data_size)

    obj = get_obj()
    res = obj.readinto(buffer)
    assert isinstance(res, int)
    assert res > 0
    assert buffer != bytearray(data_size)


def test_signature_close() -> None:
    """Test closing a signature stream."""
    obj = _get_signature()
    obj.close()
    assert obj.raw.closed
    assert obj.closed
    assert obj._job is None  # noqa: SLF001

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
    assert obj._sig is not None  # noqa: SLF001
    assert obj._job is not None  # noqa: SLF001
    assert obj._sig_job is None  # noqa: SLF001

    obj.close()
    assert obj.raw.closed
    assert obj.signature_closed
    assert obj.closed
    assert obj._job is None  # noqa: SLF001
    assert obj._sig is None  # noqa: SLF001

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
    assert obj._job is None  # noqa: SLF001

    obj.close()
    assert obj.raw.closed
    assert obj.basis_closed
    assert obj.closed
    assert obj._job is None  # noqa: SLF001

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
    assert obj._job is None  # noqa: SLF001

    with pytest.raises(ValueError, match=r"raw stream already detached"):
        obj.detach()

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
    assert obj._sig is not None  # noqa: SLF001
    assert obj._job is not None  # noqa: SLF001
    assert obj._sig_job is None  # noqa: SLF001

    with pytest.raises(ValueError, match=r"raw_signature stream already detached"):
        obj.detach_signature()

    obj.detach()
    assert obj.raw is None
    assert obj._job is None  # noqa: SLF001
    assert obj._sig is None  # noqa: SLF001

    with pytest.raises(ValueError, match=r"raw stream already detached"):
        obj.detach()

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
    assert obj._job is None  # noqa: SLF001

    with pytest.raises(ValueError, match=r"raw_basis stream already detached"):
        obj.detach_basis()

    obj.detach()
    assert obj.raw is None
    assert obj._job is None  # noqa: SLF001

    with pytest.raises(ValueError, match=r"raw stream already detached"):
        obj.detach()

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
    assert obj._job is None  # noqa: SLF001

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
        assert obj._job is not None  # noqa: SLF001

    assert obj.closed
    assert obj._job is None  # noqa: SLF001


def test_delta_context_manager_api() -> None:
    """Test delta context manager API."""
    with _get_delta() as obj:
        assert not obj.closed
        assert not obj.signature_closed
        # job should not be created until signature is loaded
        assert obj._job is None  # noqa: SLF001
        assert obj._sig is not None  # noqa: SLF001
        assert obj._sig_job is not None  # noqa: SLF001

    with _get_delta() as obj:
        obj.load_signature()
        assert not obj.closed
        assert not obj.signature_closed
        assert obj._job is not None  # noqa: SLF001
        assert obj._sig is not None  # noqa: SLF001
        assert obj._sig_job is not None  # noqa: SLF001

    assert obj.closed
    assert obj.signature_closed
    assert obj._job is None  # noqa: SLF001
    assert obj._sig is None  # noqa: SLF001
    assert obj._sig_job is None  # noqa: SLF001


def test_patch_context_manager_api() -> None:
    """Test patch context manager API."""
    with _get_patch() as obj:
        assert not obj.closed
        assert not obj.basis_closed
        assert obj._job is not None  # noqa: SLF001

    assert obj.closed
    assert obj.basis_closed
    assert obj._job is None  # noqa: SLF001


@pytest.mark.parametrize("cls", [Signature, Delta, Patch])
def test_job_stats(cls: type[Signature | Delta | Patch]) -> None:  # noqa:  PLR0915
    """Test job statistics."""
    obj: Signature | Delta | Patch

    if cls is Signature:
        obj = _get_signature()
        job_type = JobType.SIGNATURE
    elif cls is Delta:
        obj = _get_delta()
        job_type = JobType.DELTA
    else:
        obj = _get_patch()
        job_type = JobType.PATCH

    # The start time is recorded by the C API, which in turn measures
    # epoch time, so it is limited to 1s intervals. Sleep for 1 second to
    # ensure the time taken is > 0
    sleep(1)

    # Delta job is not loaded until signature is loaded
    if cls is not Delta:
        assert isinstance(obj.job_stats, JobStatistics)
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

    if isinstance(obj, Delta):
        assert isinstance(obj.signature_job_stats, JobStatistics)
        assert obj.signature_job_stats.job_type == JobType.LOAD_SIGNATURE
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

        raw_stats = _lib.rs_job_statistics(obj._sig_job)  # noqa: SLF001

        in_len = len(_get_delta().raw_signature.read())

        assert isinstance(obj.job_stats, JobStatistics)
        assert obj.signature_job_stats.job_type == JobType.LOAD_SIGNATURE
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

    raw_stats = _lib.rs_job_statistics(obj._job)  # noqa: SLF001

    assert isinstance(obj.job_stats, JobStatistics)
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
        assert obj.job_stats.time_taken == 2  # noqa: PLR2004
    assert obj.job_stats.in_speed == in_len / obj.job_stats.time_taken
    assert obj.job_stats.out_speed == out_len / obj.job_stats.time_taken

    obj.close()

    if isinstance(obj, Delta):
        with pytest.raises(
            ValueError, match=r"I/O operation on a freed librsync signature."
        ):
            obj.job_stats  # noqa: B018
        obj.close_signature()
        with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
            obj.signature_job_stats  # noqa: B018
    else:
        with pytest.raises(ValueError, match=r"I/O operation on a freed librsync job."):
            obj.job_stats  # noqa: B018


def test_delta_match_stats() -> None:
    """Test delta job match statistics."""
    text_orig = b"123" * 1024 * 100
    text_new = text_orig

    text_orig = b"666" * 100 + text_orig
    text_new += b"999" * 123

    obj = _get_delta(Signature(io.BytesIO(text_orig)), text_new)

    with pytest.raises(ValueError, match=r"Invalid signature type."):
        obj.match_stats  # noqa: B018

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
    sig = obj._sig[0][0]  # noqa: SLF001

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


def test_full_lifecycle() -> None:  # noqa: PLR0915
    """Test full lifecycle - signature, load signature, delta and patch."""
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


def test_full_lifecycle_1_byte_at_a_time() -> None:
    """Test full lifecycle byte-wise - signature, load signature, delta and patch."""

    def read_stream(obj: Signature | Delta | Patch) -> bytes:
        buffer = b""

        while True:
            chunk = obj.read(1)
            if not chunk:
                break
            buffer += chunk

            chunk = obj.read1(1)
            if not chunk:
                break
            buffer += chunk

            chunk = bytearray(1)

            read = obj.readinto(chunk)
            if not read:
                break
            buffer += chunk

            read = obj.readinto1(chunk)
            if not read:
                break
            buffer += chunk

        return buffer

    orig = ((b"123" * 256) + b"4") * 64
    new = ((b"123" * 256) + b"5") * 48

    sig_buffer = read_stream(Signature(io.BytesIO(orig), buffer_size=1))

    delta = Delta(io.BytesIO(sig_buffer), io.BytesIO(new), buffer_size=1)
    while True:
        read = delta.load_signature(1)
        if not read:
            break
        read = delta.load_signature1(1)
        if not read:
            break

    delta_buffer = read_stream(delta)
    patched_orig = read_stream(
        Patch(io.BytesIO(orig), io.BytesIO(delta_buffer), buffer_size=1)
    )

    assert new == patched_orig
