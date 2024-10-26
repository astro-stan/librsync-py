#!/usr/bin/env python3
#
# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""CFFI C ext code generator."""

from __future__ import annotations

import os
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
        "--extra-sources",
        type=lambda x: validate_source_file(argparser, x),
        nargs="+",
        help="Extra sources to pass to cffi.set_source() directly. "
        "Added before the main module header sources."
    )

    args = argparser.parse_args()

    ffibuilder = cffi.FFI()

    for header in args.headers:
        ffibuilder.cdef(header.read_text())

    sources = args.module_header.read_text() + os.linesep
    for source in args.extra_sources:
        sources += source.read_text() + os.linesep

    ffibuilder.set_source(
        args.module_name,
        sources,
    )

    ffibuilder.distutils_extension(".")
