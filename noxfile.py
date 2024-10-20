# Copyright (c) 2024 librsync-py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""The noxfile."""

from __future__ import annotations

import os
import re
from pathlib import Path

import nox  # type: ignore[import-not-found]


def _natural_sort(content: list[str]) -> list[str]:
    convert = lambda text: int(text) if text.isdigit() else text.lower()  # noqa: E731
    return sorted(
        content, key=lambda key: [convert(c) for c in re.split("([0-9]+)", key)]
    )


with Path(".python-version").open("r") as f:
    SUPPORTED_PYTHON_VERSIONS = _natural_sort(re.sub(r"[\n\s]+", " ", f.read()).split())


@nox.session(python=SUPPORTED_PYTHON_VERSIONS)
def test(session: nox.Session) -> None:
    """Run the tests."""
    session.install(".", "pytest", "pytest-cov")
    # Run pytest from `coverage`, instead of the other way around as
    # otherwise `coverage` is being loaded late which skews the coverage results
    session.run("coverage", "run", "-m", "pytest", "--cov=librsync_py", *session.posargs)


@nox.session(reuse_venv=True)
def format(session: nox.Session) -> None:  # noqa: A001
    """Format the code."""
    session.install("ruff")
    session.run("ruff", "format", *session.posargs)


@nox.session(reuse_venv=True)
def lint(session: nox.Session) -> None:
    """Lint the code."""
    session.install("ruff")
    session.run("ruff", "check", *session.posargs)


@nox.session(reuse_venv=True, name="typeCheck")
def type_check(session: nox.Session) -> None:
    """Type check the code with mypy."""
    session.install(".", "pytest", "pytest-cov", "mypy")
    if not session.posargs:
        posargs = [Path(os.path.realpath(__file__)).parent]
    else:
        posargs = session.posargs
    session.run("mypy", *posargs)


@nox.session(python=SUPPORTED_PYTHON_VERSIONS)
def wheel(session: nox.Session) -> None:
    """Build a wheel."""
    session.install("build")
    session.run("python", "-m", "build", "-w", *session.posargs)


@nox.session
def sdist(session: nox.Session) -> None:
    """Build an sdist."""
    session.install("build")
    session.run("python", "-m", "build", "-s", *session.posargs)
