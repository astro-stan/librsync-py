# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from librsync_py._internals.common import Result

if TYPE_CHECKING:
    from sys import version_info

    if version_info < (3, 11):  # pragma: no cover
        from typing_extensions import Self
    else:  # pragma: no cover
        from typing import Self


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
