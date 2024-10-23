#!/usr/bin/env python3
#
# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""CFFI C ext code generator."""

import argparse
from pathlib import Path

import cffi  # type: ignore[import-untyped]


def validate_header_file(parser, entry):
    entry = Path(entry)

    if entry.exists() and entry.is_file() and str(entry).endswith(".h"):
        return entry.absolute()

    parser.error(f"'{entry}' does not exist or is not a valid header file.")

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser = argparse.ArgumentParser(
        description="Pyext FFI generator for librsync",
    )
    argparser.add_argument(
        "headers",
        type=lambda x: validate_header_file(argparser, x),
        nargs="+",
        help="Preprocessed header files containing definitions "
        "for which to generate FFI bindings",
    )
    argparser.add_argument(
        "--module-name",
        type=str,
        required=True,
        help="The Pyext module name"
    )
    argparser.add_argument(
        "--module-header",
        type=lambda x: validate_header_file(argparser, x),
        required=True,
        help="The Pyext module header"
    )

    args = argparser.parse_args()

    ffibuilder = cffi.FFI()

    for header in args.headers:
        ffibuilder.cdef(header.read_text())

    ffibuilder.set_source(
        args.module_name,
        args.module_header.read_text(),
    )

    ffibuilder.distutils_extension('.')
