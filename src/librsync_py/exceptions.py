# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync exceptions."""

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


class Result(IntEnum):
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
    def _missing_(cls: type[Self], value: object) -> Result:
        # Return an `UNKNOWN` exception type but keep use the actual status
        unknown_enum_val = int.__new__(cls, value)  # type: ignore[call-overload]
        unknown_enum_val._name_ = Result.UNKNOWN.name
        unknown_enum_val._value_ = value
        unknown_enum_val._description_ = Result.UNKNOWN.description
        return unknown_enum_val

    def __str__(self: Self) -> str:
        """To string."""
        return f"{self.description} ({self.value})."


class RsCApiError(Exception):
    """The base for all C API librsync exceptions."""

    RESULT = Result.UNKNOWN

    def __init__(self: Self) -> None:
        """Initialise the exception."""
        super().__init__(Result(self.RESULT))

    @property
    def result(self: Self) -> Result:
        """Get the exception result code."""
        return self.args[0]


class RsUnknownError(RsCApiError):
    """Unknown librsync error."""

    def __init__(self: Self, result: int | Result | None = None) -> None:
        """Initialise an unknown error with a given status code."""
        self.RESULT = Result(result or self.RESULT)
        super().__init__()


class RsBlockedError(RsCApiError):
    """Operation failed due to being blocked waiting for more data."""

    RESULT = Result.BLOCKED


class RsRunningError(RsCApiError):
    """Operation failed due to a job still running and not finished/blocked."""

    RESULT = Result.RUNNING


class RsIoError(RsCApiError):
    """Operation failed due to error in file or network IO."""

    RESULT = Result.IO_ERROR


class RsSyntaxError(RsCApiError):
    """Operation failed due to a command line syntax error."""

    RESULT = Result.SYNTAX_ERROR


class RsMemoryError(RsCApiError):
    """Operation failed due to running out of memory."""

    RESULT = Result.MEMORY_ERROR


class RsInputEndedError(RsCApiError):
    """Operation failed due to reaching the end of an input file unexpectedly."""

    RESULT = Result.INPUT_ENDED


class RsBadMagicError(RsCApiError):
    """Operation failed due to a bad magic number at the start of a stream."""

    RESULT = Result.BAD_MAGIC


class RsUnimplementedError(RsCApiError):
    """Operation failed due to functionality not being implemented yet."""

    RESULT = Result.UNIMPLEMENTED


class RsInternalError(RsCApiError):
    """Operation failed due to an internal library error. This is likely a library bug."""

    RESULT = Result.INTERNAL_ERROR


class RsParamError(RsCApiError):
    """Operation failed due to a bad value being passed to the library. May also be a library bug."""

    RESULT = Result.PARAM_ERROR
