# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Python bindings for the librsync library."""

from librsync_py._internals.wrappers import RsSignatureMagic
from librsync_py.stream import Delta, Patch, Signature
from librsync_py.whole import delta, patch, signature

__all__ = [
    "RsSignatureMagic",
    "Signature",
    "Delta",
    "Patch",
    "signature",
    "delta",
    "patch",
]
