#!/usr/bin/env python3
#
# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Header cleaner for librsync."""

import argparse
import os
import re
from pathlib import Path


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

def validate_line_allowlist(parser, entry):
    entry = str(entry)

    if entry.count(":") != 2:
        parser.error("Invalid number of ':'. "
                     "Expected '<header_name>:<from>:<to>'."
                     "Use of an empy string for the `<header_name>` part "
                     "is allowed."
                     )
        return

    header_name, from_, to = entry.split(":")

    if header_name:
        if not header_name.endswith(".h"):
            parser.error("Only header files ('.h') are allowed.")
    else:
        header_name = None

    return header_name, (int(from_), int(to))

def aggregate_options(options):
    result = {}
    for key, value in options:
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

def is_line_allowed(header, line, allowlist):
    full_list = set()

    for key, value in allowlist.items():
        if not key or header.endswith(key):
            full_list = full_list.union(value)

    if not full_list:
        return True

    for from_, to in full_list:
        if line >= from_ and (line <= to or to == -1):
            return True

    return False

def process_header(header, header_allowlist, line_allowlist, substitutions):
    # Matches strings like:
    # `# 27 "/usr/include/x86_64-linux-gnu/bits/types.h"`
    # With capture groups for the line number and file path
    file_location_directive_regex = re.compile(r"\s*#\s+(\d+)\s+\"((?:[\/\\][^\/\\]+)+)\"")

    output = ""

    # Apply the header and line allowlist rules
    headerSkipMode = False
    lineSkipMode = False
    currentLineNum = 0
    for line in header.read_text().splitlines():
        currentLineNum += 1
        match = file_location_directive_regex.match(line)
        if match:
            currentLineNum = int(match.group(1)) - 1
            header_path = match.group(2)
            if is_header_allowed(header_path, header, header_allowlist):
                headerSkipMode = False
            else:
                headerSkipMode = True
        elif not headerSkipMode:
            if is_line_allowed(header_path, currentLineNum, line_allowlist):
                lineSkipMode = False
            else:
                lineSkipMode = True

        if not headerSkipMode and not lineSkipMode:
            output += line + os.linesep

    # Apply the regex substitution rules
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
        "for which to generate FFI bindings.",
    )
    argparser.add_argument(
        "--header-allowlist",
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
        "--line-allowlist",
        type=lambda x: validate_line_allowlist(argparser, x),
        nargs="+",
        required=False,
        default={},
        help="If provided - a list of line pairs (<from>:<to>) to keep from the input headers."
        "All other output is discarted. This step is performed AFTER the the header allowlist step. "
        "Can be specified in one of several ways. The format is: "
        "`<header_name>:<from>:<to>`. `<header_name>` part is optional. If "
        "`<header_name>` is not provided - the rule applies to all headers. "
        "If `<to> == -1` means 'to the end of the file'. "
        "Useful for removing noise from whitelisted headers.",
    )
    argparser.add_argument(
        "--substitutions",
        type=lambda x: validate_substitutions(argparser, x),
        nargs="+",
        required=False,
        default={},
        help="If provided - a list of regexes and substitutions to apply to the input headers."
        "This step is performed AFTER the the header and line allowlist steps. "
        "Can be specified in one of several ways. The format is: "
        "`<header_file>:<regex>:<substitution>`. `<header_file>` and `<substitution> "
        "parts are optional. If `<header_file>` is not provided - the regex applies "
        "to all imput files. If `<substitution>` is not provided - the matched "
        "regex will be replaced with an empty string. Using `:` as part of regex or "
        "substitution is not allowed. The regexes are applied "
        "in the same order they are specified on the command line. "
        "Useful for removing noise from whitelisted headers.",
    )
    args = argparser.parse_args()

    header_allowlist = aggregate_options(args.header_allowlist)
    line_allowlist = aggregate_options(args.line_allowlist)
    subsittutions = aggregate_options(args.substitutions)

    for header in args.headers:
        output = process_header(header, header_allowlist, line_allowlist, subsittutions)
        header.write_text(output)
