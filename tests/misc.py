# Copyright (c) 2024-2025 librsync-py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Miscellaneous tests."""

from librsync_py import LIBRSYNC_VERSION_STR


def test_librsync_version_string() -> None:
    """Test getting the librsync version string."""
    assert LIBRSYNC_VERSION_STR.startswith("librsync")
