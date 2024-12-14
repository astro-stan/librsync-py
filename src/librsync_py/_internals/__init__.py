# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
from __future__ import annotations

from enum import IntEnum
from sys import version_info
from typing import cast

from .job import JobStatistics

if version_info < (3, 11):  # pragma: no cover
    from typing_extensions import Self
else:  # pragma: no cover
    from typing import Self

try:
    from librsync_py._librsync_py import (
        ffi as _ffi,  # type: ignore[import-untyped] # noqa: F401
    )
    from librsync_py._librsync_py import lib as _lib  # type: ignore[import-untyped]
except ImportError as exc:  # pragma: no cover
    msg = "librsync_py C extension import failed, cannot use C-API"
    raise ImportError(msg) from exc


class RsResult(IntEnum):
    DONE = (cast(int, _lib.RS_DONE), "Completed successfully")
    BLOCKED = (cast(int, _lib.RS_BLOCKED), "Blocked waiting for more data")
    RUNNING = (
        cast(int, _lib.RS_RUNNING),
        "The job is still running, and not yet finished or blocked. "
        "This value should never be seen by the application",
    )
    TEST_SKIPPED = (cast(int, _lib.RS_TEST_SKIPPED), "Test neither passed or failed")
    IO_ERROR = (cast(int, _lib.RS_IO_ERROR), "Error in file or network IO")
    SYNTAX_ERROR = (cast(int, _lib.RS_SYNTAX_ERROR), "Command line syntax error")
    MEMORY_ERROR = (cast(int, _lib.RS_MEM_ERROR), "Out of memory")
    INPUT_ENDED = (
        cast(int, _lib.RS_INPUT_ENDED),
        "Unexpected end of input file, perhaps due to a "
        "truncated file or dropped network connection",
    )
    BAD_MAGIC = (
        cast(int, _lib.RS_BAD_MAGIC),
        "Bad magic number at start of stream. Probably not a "
        "librsync file, or possibly the wrong kind of file or from an incompatible library version",
    )
    UNIMPLEMENTED = (
        cast(int, _lib.RS_UNIMPLEMENTED),
        "The functionality is not implemented yet.",
    )
    INTERNAL_ERROR = (cast(int, _lib.RS_INTERNAL_ERROR), "Probably a library bug")
    PARAM_ERROR = (
        cast(int, _lib.RS_PARAM_ERROR),
        "Bad value passed in to library, usage error or application bug",
    )

    UNKNOWN = (-1, "Unknown result")

    _description_: str

    @property
    def description(self: Self) -> str:
        """Get the status description."""
        return self._description_

    def __new__(cls: type[Self], value: int, description: str = "") -> Self:
        """Create a new RSResult object."""
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj._description_ = description
        return obj

    @classmethod
    def _missing_(cls: type[Self], value: object) -> RsResult:
        # Return an `UNKNOWN` exception type but keep use the actual status
        unknown_enum_val = int.__new__(cls, value)  # type: ignore[call-overload]
        unknown_enum_val._name_ = RsResult.UNKNOWN.name
        unknown_enum_val._value_ = value
        unknown_enum_val._description_ = RsResult.UNKNOWN.description
        return unknown_enum_val

    def __str__(self: Self) -> str:
        """To string."""
        return f"{self.description} ({self.value})."


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


__all__ = [
    "JobStatistics",
    "RsResult",
    "SignatureType",
]
