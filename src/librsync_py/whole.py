# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync whole API."""

from __future__ import annotations

import io

from ._internals import SignatureType
from .stream import Delta, Patch, Signature


def signature(  # noqa: PLR0913
    basis: bytes,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
    file_size: int | None = None,
    sig_type: SignatureType = SignatureType.RK_BLAKE2_SIG,
    block_length: int = 0,
    hash_length: int = 0,
) -> bytes:
    """Generate a new signature.

    :param basis: The source file-like object
    :type basis: bytes
    :param chunk_size: The read chunk size in bytes. For data sizes above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type chunk_size: int
    :param file_size: The size of the file-like object. Set to `None` if unknown.
    :type file_size: int
    :param block_length: The signature block length. Larger values make a
    shorter signature but increase the delta file size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :type hash_length: int
    :returns: The generated signature
    :rtype: bytes
    """
    return Signature(
        raw=io.BytesIO(basis),
        buffer_size=chunk_size,
        file_size=file_size,
        signature_type=sig_type,
        block_length=block_length,
        hash_length=hash_length,
    ).read()


def delta(
    signature: bytes,
    basis: bytes,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
) -> bytes:
    """Generate a new delta.

    :param signature: The signature file-like object
    :type signature: bytes
    :param basis: The source file-like object
    :type basis: bytes
    :param chunk_size: The read chunk size in bytes. For data sizes above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type chunk_size: int
    :returns: The generated delta
    :rtype: bytes
    """
    d = Delta(
        sig_raw=io.BytesIO(signature),
        basis_raw=io.BytesIO(basis),
        buffer_size=chunk_size,
    )
    d.load_signature()
    return d.read()


def patch(
    basis: bytes,
    delta: bytes,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
) -> bytes:
    """Patch a file-like object.

    :param basis: The source file-like object
    :type basis: bytes
    :param delta: The delta file-like object
    :type delta: bytes
    :param chunk_size: The read chunk size in bytes. For data sizes above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type chunk_size: int
    :returns: The patched file-like object
    :rtype: bytes
    """
    return Patch(
        basis_raw=io.BytesIO(basis),
        delta_raw=io.BytesIO(delta),
        buffer_size=chunk_size,
    ).read()
