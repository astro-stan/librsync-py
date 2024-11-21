# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Tests for the stream API."""

from __future__ import annotations

import io
import re
from ast import Del
from turtle import bye

import pytest
from numpy import isin

from librsync_py import Delta, Patch, RsSignatureMagic, Signature


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
) -> Delta:
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
    assert s._Job__job is not None  # noqa: SLF001
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
    assert d._Job__job is not None  # noqa: SLF001
    assert d._Delta__sig_job is not None  # noqa: SLF001
    assert d._Delta__sig is not None  # noqa: SLF001
    assert d.raw_signature is sig_stream
    assert d.raw is basis_stream
    assert d.buffer_size == io.DEFAULT_BUFFER_SIZE


def test_patch_init_args() -> None:
    """Test patch init args are applied."""
    basis_stream = io.BytesIO(b"")
    delta_stream = io.BytesIO(b"")
    p = Patch(basis_stream, delta_stream)
    assert p._Job__job is not None  # noqa: SLF001
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


@pytest.mark.parametrize(
    "cls,buffer_cls",
    [
        (Signature, (memoryview, bytearray)),
        (Delta, (memoryview, bytearray)),
        (Patch, (memoryview, bytearray)),
    ],
)
def test_readinto(
    cls: type[Signature | Delta | Patch],
    buffer_cls: type[memoryview | bytearray],
) -> None:
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

    buffer = bytearray()

    res = obj.readinto(buffer)
    assert isinstance(res, int) and res == 0
    res = obj.readinto1(buffer)
    assert isinstance(res, int) and res == 0
    res = obj.readinto(memoryview(buffer))
    assert isinstance(res, int) and res == 0
    res = obj.readinto1(memoryview(buffer))
    assert isinstance(res, int) and res == 0

    buffer = bytearray(1) # Zero-init array

    res = obj.readinto(buffer)
    assert isinstance(res, int) and res == 1 and buffer != bytearray(1)
    res = obj.readinto(memoryview(buffer))
    assert isinstance(res, int) and res == 1 and buffer != bytearray(1)

    buffer = bytearray(3) # Zero-init array

    res = obj.readinto1(buffer)
    assert isinstance(res, int) and res == 3 and buffer != bytearray(3)
    res = obj.readinto1(memoryview(buffer))
    assert isinstance(res, int) and res == 3 and buffer != bytearray(3)

    buffer = bytearray(data_size)
    obj = get_obj()
    res = obj.readinto1(buffer)
    assert isinstance(res, int) and 0 < res <= buffer_size
    assert buffer != bytearray(data_size)

    # for arg in (None, -1, -2):  # < -1 should be treated as -1
    #     obj = get_obj()
    #     res = obj.read(arg)
    #     assert isinstance(res, bytes) and len(res) > 0
    #     res = obj.read(arg)
    #     assert isinstance(res, bytes) and len(res) == 0


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
