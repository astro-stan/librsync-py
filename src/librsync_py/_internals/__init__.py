# Copyright (c) 2024-2025 librsync-py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
from __future__ import annotations

try:
    from librsync_py._librsync_py import (  # type: ignore[import-untyped] # noqa: F401
        ffi as _ffi,
    )
    from librsync_py._librsync_py import (  # type: ignore[import-untyped] # noqa: F401
        lib as _lib,
    )
except ImportError as exc:  # pragma: no cover
    msg = "librsync_py C extension import failed, cannot use C-API"
    raise ImportError(msg) from exc
