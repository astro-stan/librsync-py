#!/usr/bin/env python3
#
# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Header cleaner for librsync."""

from __future__ import annotations

import os
import re
from argparse import ArgumentParser
from pathlib import Path


def validate_header_file(parser: ArgumentParser, entry: str) -> None | Path:
    """Validate the header file arg."""
    path = Path(entry)

    if path.exists() and path.is_file() and str(path).endswith(".h"):
        return path.absolute()

    parser.error(f"'{path}' does not exist or is not a valid header file.")
    return None


def validate_header_allowlist(
    parser: ArgumentParser, entry: str
) -> None | tuple[str | None, str]:
    """Validate the header allowlist option."""
    entry = str(entry)

    if entry.count(":") > 1:
        parser.error("Too many ':'.")
        return None

    header_file = None
    if ":" in entry:
        header_file, whitelisted_header = entry.split(":")
        header_file = str(validate_header_file(parser, header_file))
    else:
        whitelisted_header = entry

    if not whitelisted_header.endswith(".h"):
        parser.error("Only header files ('.h') are allowed.")

    return header_file, whitelisted_header


def validate_substitutions(
    parser: ArgumentParser, entry: str
) -> None | tuple[str | None, tuple[re.Pattern, str]]:
    """Validate the substitution option."""
    if entry.count(":") != 2:  # noqa: PLR2004
        parser.error(
            "Invalid number of ':'. "
            "Expected '<header_file>:<regex>:<substitution>'."
            "Use of empy strings for the `<header_file>` and "
            "`<substitution>` parts is allowed."
        )
        return None

    header_file: str | None
    header_file, regex, substitution = entry.split(":")

    if header_file:
        header_file = str(validate_header_file(parser, header_file))
    else:
        header_file = None

    return header_file, (re.compile(regex, flags=re.MULTILINE), substitution)


def validate_line_allowlist(
    parser: ArgumentParser, entry: str
) -> None | tuple[str | None, tuple[int, int]]:
    """Validate the line allowlist option."""
    if entry.count(":") != 2:  # noqa: PLR2004
        parser.error(
            "Invalid number of ':'. "
            "Expected '<header_name>:<from>:<to>'."
            "Use of an empy string for the `<header_name>` part "
            "is allowed."
        )
        return None

    header_name: str | None
    header_name, from_, to = entry.split(":")

    if header_name:
        if not header_name.endswith(".h"):
            parser.error("Only header files ('.h') are allowed.")
    else:
        header_name = None

    return header_name, (int(from_), int(to))


def aggregate_options(options: tuple[str, tuple | str]) -> dict[str, set]:
    """Group the options given on the command line."""
    result: dict[str, set] = {}
    for opt in options:
        result.setdefault(opt[0] if opt[0] else "", set()).add(opt[1])

    return result


def _is_header_allowed(
    header_path: str, header: Path, allowlist: dict[str, set]
) -> bool:
    """Check if a header is allowlisted."""
    default_allowlist = allowlist.get("", set())
    header_allowlist = allowlist.get(str(header), set())

    full_list = default_allowlist.union(header_allowlist)

    if not full_list:
        return True

    return any(str(header_path).endswith(entry) for entry in full_list)


def _is_line_allowed(header: str, line: int, allowlist: dict[str, set]) -> bool:
    """Check if a line in a header is allowlisted."""
    full_list: set = set()

    for key, value in allowlist.items():
        if not key or header.endswith(str(key)):
            full_list = full_list.union(value)

    if not full_list:
        return True

    return any(line >= from_ and (line <= to or to == -1) for from_, to in full_list)


def process_header(
    header: Path,
    header_allowlist: dict[str, set],
    line_allowlist: dict[str, set],
    substitutions: dict[str, set],
) -> str:
    """Process a single header."""
    # Matches strings like:
    # `# 27 "/usr/include/x86_64-linux-gnu/bits/types.h"`
    # With capture groups for the line number and file path
    file_location_directive_regex = re.compile(
        r"\s*#\s+(\d+)\s+\"((?:[\/\\][^\/\\]+)+)\""
    )

    output = ""

    # Apply the header and line allowlist rules
    header_skip_mode = False
    line_skip_mode = False
    current_line_num = 0
    for line in header.read_text().splitlines():
        current_line_num += 1
        match = file_location_directive_regex.match(line)
        if match:
            current_line_num = int(match.group(1)) - 1
            header_path = match.group(2)
            if _is_header_allowed(header_path, header, header_allowlist):
                header_skip_mode = False
            else:
                header_skip_mode = True
        elif not header_skip_mode:
            if _is_line_allowed(header_path, current_line_num, line_allowlist):
                line_skip_mode = False
            else:
                line_skip_mode = True

        if not header_skip_mode and not line_skip_mode:
            output += line + os.linesep

    # Apply the regex substitution rules
    all_substitution_rules = substitutions.get("", set()).union(
        subsittutions.get(str(header), set())
    )
    for regex, sub in all_substitution_rules:
        output = regex.sub(sub, output)

    return output


if __name__ == "__main__":
    argparser = ArgumentParser(
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
