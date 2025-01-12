# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync whole API."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

from .common import SignatureType
from .stream import Delta, Patch, Signature

if TYPE_CHECKING:  # pragma: no cover
    from sys import version_info

    if version_info < (3, 11):  # pragma: no cover
        from typing_extensions import Buffer
    else:  # pragma: no cover
        from collections.abc import Buffer


def signature(  # noqa: PLR0913
    basis: Buffer | io.RawIOBase | io.BytesIO,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
    file_size: int | None = None,
    sig_type: SignatureType = SignatureType.RK_BLAKE2,
    block_length: int = 0,
    hash_length: int = 0,
) -> bytes:
    """Generate a new signature from a file-like or bytes-like object.

    :param basis: The source file-like or bytes-like object
    :type basis: Union[Buffer, io.RawIOBase, io.BytesIO]
    :param chunk_size: The read chunk size in bytes. For data sizes above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type chunk_size: int
    :param file_size: The size of the file-like or bytes-like object. Set to
    `None` if unknown.
    :type file_size: int
    :param block_length: The signature block length. Larger values make a
    shorter signature but increase the delta file size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :type hash_length: int
    :returns: The generated signature object
    :rtype: bytes
    """
    if not isinstance(basis, (io.RawIOBase, io.BytesIO)):
        basis = io.BytesIO(basis)

    return Signature(
        raw=basis,
        buffer_size=chunk_size,
        file_size=file_size,
        signature_type=sig_type,
        block_length=block_length,
        hash_length=hash_length,
    ).read()


def delta(
    signature: Buffer | io.RawIOBase | io.BytesIO,
    basis: Buffer | io.RawIOBase | io.BytesIO,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
) -> bytes:
    """Generate a new delta from a file-like or bytes-like object.

    :param signature: The signature file-like or bytes-like object
    :type signature: Union[Buffer, io.RawIOBase, io.BytesIO]
    :param basis: The source file-like or bytes-like object
    :type basis: Union[Buffer, io.RawIOBase, io.BytesIO]
    :param chunk_size: The read chunk size in bytes. For data sizes above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type chunk_size: int
    :returns: The generated delta object
    :rtype: bytes
    """
    if not isinstance(signature, (io.RawIOBase, io.BytesIO)):
        signature = io.BytesIO(signature)
    if not isinstance(basis, (io.RawIOBase, io.BytesIO)):
        basis = io.BytesIO(basis)

    d = Delta(
        sig_raw=signature,
        basis_raw=basis,
        buffer_size=chunk_size,
    )
    d.load_signature()
    return d.read()


def patch(
    basis: Buffer | io.RawIOBase | io.BytesIO,
    delta: Buffer | io.RawIOBase | io.BytesIO,
    chunk_size: int = io.DEFAULT_BUFFER_SIZE,
) -> bytes:
    """Patch a file-like or bytes-like object.

    :param basis: The source file-like or bytes-like object
    :type basis: Union[Buffer, io.RawIOBase, io.BytesIO]
    :param delta: The delta file-like or bytes-like object
    :type delta: Union[Buffer, io.RawIOBase, io.BytesIO]
    :param chunk_size: The read chunk size in bytes. For data sizes above
    1GB, good values are typically in the range of 1MB-16MB. Experimentation
    and/or profiling may be needed to achieve optimal results
    :type chunk_size: int
    :returns: The patched object
    :rtype: bytes
    """
    if not isinstance(basis, (io.RawIOBase, io.BytesIO)):
        basis = io.BytesIO(basis)
    if not isinstance(delta, (io.RawIOBase, io.BytesIO)):
        delta = io.BytesIO(delta)

    return Patch(
        basis_raw=basis,
        delta_raw=delta,
        buffer_size=chunk_size,
    ).read()
