#!/usr/bin/env python3
#
# Copyright (c) 2024 pyitc project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""CFFI C ext code generator."""

import argparse
import os
import re
import sys
from pathlib import Path

import cffi  # type: ignore[import-untyped]

PREPROCESSED_FILE_LOCATION_DIRECTIVE_REGEX = re.compile(r"\s*#\s+\d+\s+\"((?:[\/\\][^\/\\]+)+)\"")

# if len(sys.argv) != 4:  # noqa: PLR2004
#     msg = "Requires three arguments"
#     raise RuntimeError(msg)


# time_header_file = Path(sys.argv[1])
# header_file = Path(sys.argv[2])
# module_name = sys.argv[3]


# # Contains the preprocessed contents of the standard time.h header
# time_h_contents = time_header_file.read_text()

# # Extract only the definition of the `time_t` type from GCC time.h
# # implemenatation on linux
# time_t_typedef = re.sub(
#     r"^(?!.*typedef\s+.*time_t\s*;\n).*",
#     "",
#     time_h_contents,
#     flags=re.MULTILINE,
# )

# ffibuilder.cdef(time_t_typedef)
# ffibuilder.cdef(header_file.read_text())

# ffibuilder.set_source(
#     module_name,
#     '#include "librsync.h"',
# )

def validate_header_file(parser, entry):
    entry = Path(entry)

    if entry.exists() and entry.is_file() and str(entry).endswith(".h"):
        return entry.absolute()

    parser.error(f"'{entry}' does not exist or is not a valid header file.")

def validate_header_allowlist(parser, entry):
    entry = str(entry)

    if entry.count(":") > 1:
        parser.error("Too many ':'.")
        return

    header_file = None
    if ":" in entry:
        header_file, whitelisted_header = entry.split(":")
        header_file = str(validate_header_file(parser, header_file))
    else:
        whitelisted_header = entry

    if not whitelisted_header.endswith(".h"):
        parser.error("Only header files ('.h') are allowed.")

    return header_file, whitelisted_header

def validate_substitutions(parser, entry):
    entry = str(entry)

    if entry.count(":") != 2:
        parser.error("Invalid number of ':'. "
                     "Expected '<header_file>:<regex>:<substitution>'."
                     "Use of empy strings for the `<header_file>` and "
                     "`<substitution>` parts is allowed."
                     )
        return

    header_file, regex, substitution = entry.split(":")

    if header_file:
        header_file = str(validate_header_file(parser, header_file))
    else:
        header_file = None

    return header_file, (re.compile(regex, flags=re.MULTILINE), substitution)

def aggregate_allowlist(header_allowlist):
    result = {}
    for key, value in header_allowlist:
        result.setdefault(key if key else '', set()).add(value)

    return result

def aggregate_substitutions(substitutions):
    result = {}
    for key, value in substitutions:
        result.setdefault(key if key else '', set()).add(value)

    return result

def is_header_allowed(header_path, header, allowlist):
    default_allowlist = allowlist.get('', set())
    header_allowlist = allowlist.get(str(header), set())

    full_list = default_allowlist.union(header_allowlist)

    if not full_list:
        return True

    for entry in full_list:
        if str(header_path).endswith(entry):
            return True

    return False

def process_header(header, header_allowlist, substitutions):
    output = ""

    # Apply the header whitelist rules
    skipMode = False
    for line in header.read_text().splitlines():
        match = PREPROCESSED_FILE_LOCATION_DIRECTIVE_REGEX.match(line)
        if match:
            header_path = match.group(1)
            if is_header_allowed(header_path, header, header_allowlist):
                skipMode = False
            else:
                skipMode = True

        if not skipMode:
            output += line + os.linesep

    # Apply the substitution rules
    all_substitution_rules = substitutions.get('', set()).union(subsittutions.get(str(header), set()))
    for regex, sub in all_substitution_rules:
        output = regex.sub(sub, output)

    return output



if __name__ == "__main__":
    argparser = argparse.ArgumentParser(
        description="Header cleaner for librsync",
    )
    argparser.add_argument(
        "headers",
        type=lambda x: validate_header_file(argparser, x),
        nargs="+",
        help="Preprocessed header files containing definitions "
        "for which to generate FFI bindings",
    )
    argparser.add_argument(
        "--allowlist",
        type=lambda x: validate_header_allowlist(argparser, x),
        nargs="+",
        required=False,
        default={},
        help="If provided - a list of header names for which to generate FFI bindings. "
        "All other output present in the preprocessed input header files will be discarded. "
        "Can be specified in one of 2 ways: `<header_name>` (applies to all input "
        "header files), or `<header_file>:<header_name>` (applies only to the "
        "specified input `<header_file>`). Useful for removing noise coming from "
        "system or indirectly included headers.",
    )
    argparser.add_argument(
        "--substitutions",
        type=lambda x: validate_substitutions(argparser, x),
        nargs="+",
        required=False,
        default={},
        help="If provided - a list of regexes and substitutions to apply to the input headers."
        "This step is performed AFTER the the header allowlist step. "
        "Can be specified in one of several ways. The format is: "
        "`<header_file>:<regex>:<substitution>`. `<header_file>` and `<substitution> "
        "parts are optional. If `<header_file>` is not provided - the regex applies "
        "to all imput files. If `<substitution>` is not provided - the matched "
        "regex will be replaced with an empty string. Usung `:` as part of regex or "
        "substitution is not allowed. The regexes are applied "
        "in the same order they are specified on the command line. "
        "Useful for removing noise from whitelisted headers.",
    )
    args = argparser.parse_args()

    allowlist = aggregate_allowlist(args.allowlist)
    subsittutions = aggregate_substitutions(args.substitutions)

    ffibuilder = cffi.FFI()

    for header in args.headers:
        output = process_header(header, allowlist, subsittutions)
        header.write_text(output)
