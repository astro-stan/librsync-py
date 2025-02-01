# Copyright (c) 2024-2025 librsync-py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Common librsync objects."""

from __future__ import annotations

from enum import IntEnum
from typing import cast

from librsync_py._internals import _lib


class SignatureType(IntEnum):
    """A 4-byte magic number emitted in network-order at the start of librsync signature files.

    Used to differentiate the type of signature contained in a file.
    """

    MD4 = cast(int, _lib.RS_MD4_SIG_MAGIC)
    """A signature file with MD4 signatures.

    Backward compatible with librsync < 1.0, but strongly deprecated because
    it creates a security vulnerability on files containing partly untrusted
    data. See <https://github.com/librsync/librsync/issues/5>.
    """

    RK_MD4 = cast(int, _lib.RS_RK_MD4_SIG_MAGIC)
    """A signature file with RabinKarp rollsum and MD4 hash.

    Uses a faster/safer rollsum, but still strongly discouraged because of
    MD4's security vulnerability. Supported since librsync 2.2.0.
    """

    BLAKE2 = cast(int, _lib.RS_BLAKE2_SIG_MAGIC)
    """A signature file using the BLAKE2 hash. Supported from librsync 1.0."""

    RK_BLAKE2 = cast(int, _lib.RS_RK_BLAKE2_SIG_MAGIC)
    """A signature file with RabinKarp rollsum and BLAKE2 hash.

    Uses a faster/safer rollsum together with the safer BLAKE2 hash. This is
    the recommended default supported since librsync 2.2.0.
    """
