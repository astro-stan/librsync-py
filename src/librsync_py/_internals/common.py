# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, cast

from librsync_py._internals import _lib

if TYPE_CHECKING:
    from sys import version_info

    if version_info < (3, 11):  # pragma: no cover
        from typing_extensions import Self
    else:  # pragma: no cover
        from typing import Self


class RsResult(IntEnum):
    """librsync status codes returned by the C API."""

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
        "Bad magic number at start of stream. Probably not a librsync file, or "
        "possibly the wrong kind of file or from an incompatible library version",
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
