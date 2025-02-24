# Copyright (c) 2024-2025 librsync-py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Python bindings for the librsync library."""

from librsync_py.common import SignatureType
from librsync_py.stats import JobStatistics, JobType, MatchStatistics
from librsync_py.stream import Delta, Patch, Signature
from librsync_py.whole import delta, patch, signature

from ._internals.wrappers import get_lib_version_str as _get_lib_version_str

LIBRSYNC_VERSION_STR: str = _get_lib_version_str()
"""The librsync version string as returned by the C API."""

__all__ = [
    "LIBRSYNC_VERSION_STR",
    "Delta",
    "JobStatistics",
    "JobType",
    "MatchStatistics",
    "Patch",
    "Signature",
    "SignatureType",
    "delta",
    "patch",
    "signature",
]
