# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
try:
    from librsync_py._librsync_py import (
        ffi as _ffi,  # type: ignore[import-untyped] # noqa: F401
    )
    from librsync_py._librsync_py import (
        lib as _lib,  # type: ignore[import-untyped] # noqa: F401
    )
except ImportError as exc:  # pragma: no cover
    msg = "librsync_py C extension import failed, cannot use C-API"
    raise ImportError(msg) from exc
