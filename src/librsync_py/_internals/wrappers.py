# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html

from __future__ import annotations

from enum import IntEnum
from sys import version_info
from typing import cast

from librsync_py.exceptions import RsCApiError, RsUnknownError

from . import _ffi, _lib

if version_info < (3, 11):  # pragma: no cover
    from typing_extensions import Self
else:  # pragma: no cover
    from typing import Self


class RsResult(IntEnum):
    DONE = (cast(int, _lib.RS_DONE), "Completed successfully")
    BLOCKED = (cast(int, _lib.RS_BLOCKED), "Blocked waiting for more data")
    RUNNING = (
        cast(_lib.RS_RUNNING),
        "The job is still running, and not yet finished or blocked. "
        "This value should never be seen by the application",
    )
    TEST_SKIPPED = (cast(_lib.RS_TEST_SKIPPED), "Test neither passed or failed")
    IO_ERROR = (cast(_lib.RS_IO_ERROR), "Error in file or network IO")
    SYNTAX_ERROR = (cast(_lib.RS_SYNTAX_ERROR), "Command line syntax error")
    MEMORY_ERROR = (cast(_lib.RS_MEM_ERROR), "Out of memory")
    INPUT_ENDED = (
        cast(_lib.RS_INPUT_ENDED),
        "Unexpected end of input file, perhaps due to a "
        "truncated file or dropped network connection",
    )
    BAD_MAGIC = (
        cast(_lib.RS_BAD_MAGIC),
        "Bad magic number at start of stream. Probably not a "
        "librsync file, or possibly the wrong kind of file or from an incompatible library version",
    )
    UNIMPLEMENTED = (
        cast(_lib.RS_UNIMPLEMENTED),
        "The functionality is not implemented yet.",
    )
    INTERNAL_ERROR = (cast(_lib.RS_INTERNAL_ERROR), "Probably a library bug")
    PARAM_ERROR = (
        cast(_lib.RS_PARAM_ERROR),
        "Bad value passed in to library, probably an application bug",
    )

    UNKNOWN = (-1, "Unknown result")

    _description_: str

    @property
    def description(self: Self) -> str:
        """Get the status description."""
        return self._description_

    def __new__(cls: type[Self], value: int, description: str = "") -> Self:
        """Create a new RSResult object."""
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj._description_ = description
        return obj

    @classmethod
    def _missing_(cls: type[Self], value: object) -> RsResult:
        # Return an `UNKNOWN` exception type but keep use the actual status
        unknown_enum_val = int.__new__(cls, value)  # type: ignore[call-overload]
        unknown_enum_val._name_ = RsResult.UNKNOWN.name
        unknown_enum_val._value_ = value
        unknown_enum_val._description_ = RsResult.UNKNOWN.description
        return unknown_enum_val

    def __str__(self: Self) -> str:
        """To string."""
        return f"{self.description} ({self.value})."


class RsDeltaMagic(IntEnum):
    DELTA = cast(int, _lib.RS_DELTA_MAGIC)
    """A delta file."""


class RsSignatureMagic(IntEnum):
    MD4_SIG = cast(int, _lib.RS_MD4_SIG_MAGIC)
    """A signature file with MD4 signatures.

    Backward compatible with librsync < 1.0, but strongly deprecated because
    it creates a security vulnerability on files containing partly untrusted
    data. See <https://github.com/librsync/librsync/issues/5>.
    """

    RK_MD4_SIG = cast(int, _lib.RS_RK_MD4_SIG_MAGIC)
    """A signature file with RabinKarp rollsum and MD4 hash.

    Uses a faster/safer rollsum, but still strongly discouraged because of
    MD4's security vulnerability. Supported since librsync 2.2.0.
    """

    BLAKE2_SIG = cast(int, _lib.RS_BLAKE2_SIG_MAGIC)
    """A signature file using the BLAKE2 hash. Supported from librsync 1.0."""

    RK_BLAKE2_SIG = cast(int, _lib.RS_RK_BLAKE2_SIG_MAGIC)
    """A signature file with RabinKarp rollsum and BLAKE2 hash.

    Uses a faster/safer rollsum together with the safer BLAKE2 hash. This is
    the recommended default supported since librsync 2.2.0.
    """


class RsMagic(RsDeltaMagic, RsSignatureMagic):
    """A 4-byte magic number emitted in network-order at the start of librsync files.

    Used to differentiate the type of data contained in the file.
    """


def _handle_rs_result(
    result: int | RsResult,
    *,
    raise_on_non_error_results: bool = True,
) -> RsResult:
    """Check the operation result and raise an appropriate :class:`RsCApiError` if needed.

    :param result: The result of the operation
    :type result: int | RsResult
    :param raise_on_non_error_results: Whether or not non-erronous results should raise
    an :class:`RsCApiError`. NOTE: RsResult.DONE is not affected by this setting and will
    never raise an exception.
    :type raise_on_non_error_results: bool
    :returns: Non-erronous RsResult
    :rtype: RsResult
    :raises ItcCApiError: The appropriate exception subclass for the given RsResult
    """

    if result == RsResult.DONE:
        return RsResult(result)

    if raise_on_non_error_results and result in (
        RsResult.BLOCKED,
        RsResult.RUNNING,
    ):
        return RsResult(result)

    exc_candidates = [x for x in RsCApiError.__subclasses__() if result == x.RESULT]

    if not exc_candidates:  # pragma: no cover
        raise RsUnknownError(result)

    raise exc_candidates[0]


def get_sig_args(
    filesize: int = 0,
    sig_magic: RsSignatureMagic | int = 0,
    block_length: int = 0,
    hash_length: int = 0,
) -> tuple[RsMagic, int, int]:
    """Get recommended arguments for generating a file signature.

    :param filesize: The size of the file.
    :type filesize: int
    :param sig_magic: The signature type. Use 0 for recommended.
    :type sig_magic: RsSignatureMagic | int
    :param block_length: The signature block length. Larger values make
    a shorter signature but increase the delta size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :returns: A 3-tuple containing the RsMagic, block_length and hash_length
    in that order.
    :rtype: tuple[RsMagic, int, int]
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    # TODO: Should hash_length be checked against min and max allowed value?
    # The C code does this but also prints out nasty warning/error messages
    # to stdout
    if (
        filesize < 0
        or (not isinstance(sig_magic, RsSignatureMagic) and sig_magic != 0)
        or block_length < 0
        or hash_length < -1
    ):
        _handle_rs_result(RsResult.PARAM_ERROR)
    else:
        sig_magic_p = _ffi.new("rs_magic_number *", sig_magic)
        block_length_p = _ffi.new("size_t *", block_length)
        hash_length_p = _ffi.new("size_t *", hash_length)

        _handle_rs_result(
            _lib.rs_sig_args(filesize, sig_magic_p, block_length_p, hash_length_p),
            raise_on_non_error_results=False,
        )

        return RsMagic(sig_magic_p[0]), block_length_p[0], hash_length_p[0]
