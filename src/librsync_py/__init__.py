# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Python bindings for the librsync library."""

from librsync_py._internals import RsSignatureMagic
from librsync_py.stream import Delta, Patch, Signature
from librsync_py.whole import delta, patch, signature

from ._internals.wrappers import get_lib_version_str as _get_lib_version_str

LIBRSYNC_VERSION_STR: str = _get_lib_version_str()
"""The librsync version string as returned by the C API."""

__all__ = [
    "LIBRSYNC_VERSION_STR",
    "RsSignatureMagic",
    "Signature",
    "Delta",
    "Patch",
    "signature",
    "delta",
    "patch",
]
