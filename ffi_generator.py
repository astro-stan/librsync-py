#!/usr/bin/env python3
#
# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""CFFI C ext code generator."""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path

import cffi  # type: ignore[import-untyped]


def validate_header_file(parser: ArgumentParser, entry: str) -> None | Path:
    """Validate a header file arg."""
    path = Path(entry)

    if path.exists() and path.is_file() and str(path).endswith(".h"):
        return path.absolute()

    parser.error(f"'{path}' does not exist or is not a valid header file.")
    return None


def validate_source_file(parser: ArgumentParser, entry: str) -> None | Path:
    """Validate a source file arg."""
    path = Path(entry)

    if path.exists() and path.is_file() and str(path).endswith(".c"):
        return path.absolute()

    parser.error(f"'{path}' does not exist or is not a valid source file.")
    return None


def compute_time_t_definition(size_hint: int | None) -> str:
    """Use heuristics to define the `time_t` type."""
    import ctypes
    import platform

    type_map = {
        # Signed types
        "c": "char",
        "b": "signed char",
        "h": "short",
        "i": "int",
        "l": "long",
        "q": "long long",
        "n": "ssize_t",
        # unsigned types
        "B": "unsigned char",
        "H": "unsigned short",
        "I": "unsigned int",
        "L": "unsigned long",
        "Q": "unsigned long long",
        "N": "size_t",
        # real types
        "f": "float",
        "d": "double",
    }

    size_hint_map = {
        # Signed types
        "cbhilqn": {
            2: ctypes.c_int16,
            4: ctypes.c_int32,
            8: ctypes.c_int64,
        },
        # Unsigned types
        "BHILQN": {
            2: ctypes.c_uint16,
            4: ctypes.c_uint32,
            8: ctypes.c_uint64,
        },
        # Real types
        "fd": {
            4: ctypes.c_float,
            8: ctypes.c_double,
        },
    }

    if hasattr(ctypes, "c_time_t"):
        # c_time_c was added in Python 3.12
        time_t = ctypes.c_time_t
    # If c_time_t does not exist make an educated guess.
    # Based on: https://stackoverflow.com/a/75904657
    elif platform.system() == "Windows":
        # Assume 64-bit time_t on Windows
        time_t = ctypes.c_int64
    elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_int64):
        # 64-bit platform of any kind - assume 64-bit time_t
        time_t = ctypes.c_int64
    else:
        # assume some kind of 32-bit platform
        time_t = ctypes.c_int32

    if size_hint and ctypes.sizeof(time_t) != size_hint:
        # Assuming the heuristics gave the correct type (signed, unsigned, real)
        # but got the size wrong. Examples of this are:
        # - Compiling 32-bit binaries on a 64-bit system
        # - Compiling 32-bit binary on a 32-bit system with Y2K38 patch
        for key, size_to_type_map in size_hint_map.items():
            if time_t._type_ in key:  # type: ignore [union-attr]
                try:
                    time_t = size_to_type_map[size_hint]  # type: ignore [index]
                    break
                except KeyError:
                    msg = (
                        f"Cannot represent type {time_t._type_} "  # type: ignore [union-attr]
                        f"as an {size_hint}-byte type."
                    )
                    raise ValueError(msg) from None

    if time_t._type_ not in type_map:  # type: ignore [union-attr]
        msg = f"Unexpected 'time_t' type: {time_t._type_}"  # type: ignore [union-attr]
        raise ValueError(msg)
    time_t_type = type_map[time_t._type_]  # type: ignore [union-attr]

    return f"typedef {time_t_type} time_t;"


if __name__ == "__main__":
    argparser = ArgumentParser(
        description="Pyext FFI generator for librsync",
    )
    argparser.add_argument(
        "headers",
        type=lambda x: validate_header_file(argparser, x),
        nargs="+",
        help="The preprocessed header files containing definitions "
        "for which to generate FFI bindings.",
    )
    argparser.add_argument(
        "--module-name", type=str, required=True, help="The Pyext module name."
    )
    argparser.add_argument(
        "--module-header",
        type=lambda x: validate_header_file(argparser, x),
        required=True,
        help="The Pyext module header.",
    )
    argparser.add_argument(
        "--define-time-t",
        action="store_true",
        default=False,
        required=False,
        help="Use heuristics to define the `time_t` type. This type is not "
        "guaranteed in the C specification and therefore this is definition "
        "is best-effort. If this flag is not provided, 'time_t' must be defined "
        "in one of the provided preprocessed header files.",
    )
    argparser.add_argument(
        "--time-t-sizeof-hint",
        type=int,
        default=None,
        required=False,
        help="Provide a hint of what the size of `time_t` should be in bytes."
        "This will be used to improve the heuristics for determining its type."
        "If `--define-time-t` is not provided this option has no effect.",
    )

    args = argparser.parse_args()

    ffibuilder = cffi.FFI()

    if args.define_time_t:
        print("Using heuristics to define the 'time_t' type...")  # noqa: T201
        time_t_def = compute_time_t_definition(args.time_t_sizeof_hint)
        print(f"Defining 'time_t' as: '{time_t_def}'")  # noqa: T201
        ffibuilder.cdef(time_t_def)

    for header in args.headers:
        ffibuilder.cdef(header.read_text())

    ffibuilder.set_source(
        args.module_name,
        args.module_header.read_text(),
    )

    ffibuilder.distutils_extension(".")
