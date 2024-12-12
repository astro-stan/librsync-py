# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Tests of the exception classes."""

from librsync_py import exceptions


def test_unknown_error() -> None:
    """Test instantiating an unknown error exception."""
    assert exceptions.RsUnknownError(123).result == 123  # noqa: PLR2004
    assert exceptions.RsUnknownError(123).result.description == "Unknown result"
    assert str(exceptions.RsUnknownError(123)) == "Unknown result (123)."
