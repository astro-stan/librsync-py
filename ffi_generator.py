#!/usr/bin/env python3
#
# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""CFFI C ext code generator."""

import re
import sys
from pathlib import Path

import cffi  # type: ignore[import-untyped]

if len(sys.argv) != 4:  # noqa: PLR2004
    msg = "Requires three arguments"
    raise RuntimeError(msg)

time_header_file = Path(sys.argv[1])
header_file = Path(sys.argv[2])
module_name = sys.argv[3]

ffibuilder = cffi.FFI()

# Contains the preprocessed contents of the standard time.h header
time_h_contents = time_header_file.read_text()

# Extract only the definition of the `time_t` type from GCC time.h
# implemenatation on linux
time_t_typedef = re.sub(
    r"^(?!.*typedef\s+.*time_t\s*;\n).*",
    "",
    time_h_contents,
    flags=re.MULTILINE,
)

ffibuilder.cdef(time_t_typedef)
ffibuilder.cdef(header_file.read_text())

ffibuilder.set_source(
    module_name,
    '#include "librsync.h"',
)

if __name__ == "__main__":
    ffibuilder.distutils_extension(".")
