# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html

from __future__ import annotations

import io
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING, Any, Callable, cast
from weakref import WeakKeyDictionary

from librsync_py._internals import RsResult
from librsync_py.exceptions import RsCApiError, RsUnknownError

from . import _ffi, _lib

if TYPE_CHECKING:  # pragma: no cover
    from types import TracebackType

    from cffi.backend_ctypes import CTypesData  # type: ignore[import-untyped]


_MAX_COPY_OP_RETRIES = 10
"""The maximum number of retries allowed when trying to copy data from the
basis file during a patch iteration. See :meth:`_patch_copy_callback` for more
information.
"""

_SLEEP_DURATION_BETWEEN_COPY_OP_RETRIES = 0.05
"""In seconds. The delay between retries to copy data from a basis file during
a patch iteration. The thread running :meth:`job_iter` will be blocked for this
amount of time after each unsuccessful attempt to copy data from the basis file.
See :meth:`_patch_copy_callback` for more information.
"""


_global_weakkeydict = WeakKeyDictionary()
"""Used to keep nested cdata objects alive until parent cdata object is GCed"""


class RsDeltaMagic(IntEnum):
    """A 4-byte magic number emitted in network-order at the start of librsync files.

    Used to differentiate the type of data contained in the file.
    """

    DELTA = cast(int, _lib.RS_DELTA_MAGIC)
    """A delta file."""


class RsSignatureMagic(IntEnum):
    """A 4-byte magic number emitted in network-order at the start of librsync files.

    Used to differentiate the type of data contained in the file.
    """

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


@dataclass(frozen=True, kw_only=True)
class JobStats:
    """librsync job statistics."""

    class JobType(StrEnum):
        """librsync job type."""

        NOOP = ""
        DELTA = "delta"
        PATCH = "patch"
        LOAD_SIGNATURE = "loadsig"
        SIGNATURE = "signature"

    job_type: JobType
    """Human-readable name of current operation."""
    lit_cmds: int
    """Number of literal commands."""
    lit_bytes: int
    """Number of literal bytes."""
    lit_cmdbytes: int
    """Number of bytes used in literal command headers."""

    copy_cmds: int
    """Number of copy commands."""
    copy_bytes: int
    """Number of copied bytes."""
    copy_cmdbytes: int
    """Number of bytes used in copy command headers."""

    sig_cmds: int
    """Number of signature commands."""
    sig_bytes: int
    """Number of signature bytes."""

    false_matches: int
    """Number of false matches."""

    sig_blocks: int
    """Number of blocks described by the signature."""

    block_len: int
    """The block length."""

    in_bytes: int
    """Total bytes read from input."""

    out_bytes: int
    """Total bytes written to output."""

    start_time: datetime
    """The start time."""

    completion_time: datetime | None
    """The time the job completed. None if the job has not completed yet."""

    @property
    def time_taken(self) -> float:
        """The amount of time taken to complete the job (in seconds).

        If the job has not completed yet, the time taken up to this point is
        returned.
        """
        completion_time = self.completion_time or datetime.now(timezone.utc)
        return (completion_time - self.start_time).total_seconds()

    @property
    def in_speed(self) -> float:
        """The input stream speed in B/s.

        If the job has not completed yet, the speed up to this point is returned.
        """
        if not self.in_bytes:
            return 0.0
        return float(self.in_bytes / (self.time_taken or 1))

    @property
    def out_speed(self) -> float:
        """The output stream speed in B/s.

        If the job has not completed yet, the speed up to this point is returned.
        """
        if not self.out_bytes:
            return 0.0
        return float(self.out_bytes / (self.time_taken or 1))


@dataclass(frozen=True, kw_only=True)
class MatchStats:
    """Delta file match statistics."""

    find_count: int
    """The number of finds tried."""
    match_count: int
    """The number of matches found."""
    hashcmp_count: int
    """The number of hash compares done."""
    entrycmp_count: int
    """The number of entry compares done."""
    strongsum_calc_count: int
    """The number of strong sum calculations done."""

    @property
    def weaksumcmp_count(self) -> int:
        """The number of weak sum compares done."""
        return self.hashcmp_count

    @property
    def strongsumcmp_count(self) -> int:
        """The number of strong sum compares done."""
        return self.entrycmp_count

    @property
    def hashcmp_ratio(self) -> float:
        """The ratio of hash to total compares done."""
        if not (self.hashcmp_count and self.find_count):
            return 1.0
        return float(self.hashcmp_count / self.find_count)

    @property
    def weaksumcmp_ratio(self) -> float:
        """The ratio of weak sum to total compares done."""
        return self.hashcmp_ratio

    @property
    def entrycmp_ratio(self) -> float:
        """The ratio of entry to total compares done."""
        if not (self.entrycmp_count and self.find_count):
            return 1.0
        return float(self.entrycmp_count / self.find_count)

    @property
    def strongsumcmp_ratio(self) -> float:
        """The ratio of strong sum to total compares done."""
        return self.entrycmp_ratio

    @property
    def match_ratio(self) -> float:
        """The match ratio.

        For signatures with equal block and hash lengths, higher match ratio
        results in smaller delta file sizes.
        """
        if not (self.match_count and self.find_count):
            return 1.0
        return float(self.match_count / self.find_count)

    @property
    def strongsum_calc_ratio(self) -> float:
        """The ratio of strong sum to total calculations done."""
        if not (self.strongsum_calc_count and self.find_count):
            return 1.0
        return float(self.strongsum_calc_count / self.find_count)


@dataclass
class _PatchHandle:
    """A helper class used during patching iterations.

    Used to pass references to python objects between the following methods:
    - :meth:`_patch_copy_callback`: Used to get a reference of the `basis` object.
    - :meth:`_on_patch_copy_error`: Used to set a reference to an `exc` object
      (if one was raised while inside :meth:`_patch_copy_callback`).
    - :meth:`patch_begin`: Used to set the reference to the `basis` object.
    - :meth:`job_iter`: Used to get the refence to the `exc` object (if any)
    """

    basis: io.BufferedIOBase | io.RawIOBase
    """A binary file-like object open for reading and supporting random access
    (`.seek()`).
    """
    exc: Exception | None = None
    """An exception raised from inside the :meth:`_patch_copy_callback` method
    (if any)."""

    def __setattr__(self, name: str, value: Any) -> None:  # noqa: ANN401
        """Run validation on each attribute set."""
        super().__setattr__(name, value)
        validator = getattr(self, "validate_" + name, None)
        if callable(validator):
            validator()

    def validate_basis(self) -> None:
        """Validate basis."""
        err = ""
        if not isinstance(self.basis, (io.BufferedIOBase, io.RawIOBase)):
            err = "basis: Expected a binary file-like object."
        elif self.basis.closed or not self.basis.readable():
            err = "basis: Expected a file-like object that is open for reading."
        elif not self.basis.seekable():
            err = "basis: Expected a file-like object which supports random access (.seek())."

        if err:
            raise ValueError(err)

    def validate_exc(self) -> None:
        """Validate exc."""
        err = ""
        if not (self.exc is None or isinstance(self.exc, BaseException)):
            err = "exc: Expected an instance of BaseException() or None"

        if err:
            raise ValueError(err)


def _handle_rs_result(
    result: int | RsResult,
    *,
    raise_on_non_error_results: bool = True,
) -> RsResult:
    """Check the operation result and raise an appropriate :class:`RsCApiError` if needed.

    :param result: The result of the operation
    :type result: Union[int, RsResult]
    :param raise_on_non_error_results: Whether or not non-erronous results should raise
    an :class:`RsCApiError`. NOTE: RsResult.DONE is not affected by this setting and will
    never raise an exception.
    :type raise_on_non_error_results: bool
    :returns: Non-erronous RsResult
    :rtype: RsResult
    :raises RsCApiError: The appropriate exception subclass for the given RsResult
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


def _new_rs_buffers_t_p_handle(
    input_: bytes,
    output: bytearray,
    *,
    eof: bool = False,
) -> CTypesData:
    """Allocate a new rs_buffers_t handle.

    This handle will be automatically freed when no longer referenced.

    :param input: The input buffer
    :type input: bytes
    :param output: The output buffer
    :type output: bytearray
    :param eof: True if this is the last input data from a given input stream.
    :type eof: bool
    :returns: The rs_buffers_t handle
    :rtype: CTypesData
    """
    buffers_p = _ffi.new("rs_buffers_t *")

    in_buf_p = _ffi.from_buffer("char[]", input_, require_writable=False)
    buffers_p[0].next_in = in_buf_p
    buffers_p[0].avail_in = len(in_buf_p)

    out_buf_p = _ffi.from_buffer("char[]", output, require_writable=True)
    buffers_p[0].next_out = out_buf_p
    buffers_p[0].avail_out = len(out_buf_p)

    buffers_p[0].eof_in = eof

    # Keep input and output buffers alive until the parent struct is GCed
    _global_weakkeydict[buffers_p] = (in_buf_p, out_buf_p)

    return buffers_p


def _new_rs_signature_t_pp_handle() -> CTypesData:
    """Allocate a new rs_signature_t handle.

    This handle will be automatically freed when no longer referenced.
    """
    return _ffi.new("rs_signature_t **")


def _get_rs_buffers_t_unused_input_data_size(buffers_p: CTypesData) -> int:
    """Get the size of the unused intput data buffer inside `rs_buffers_t`.

    :param buffers_p: The rs_buffers_t handle
    :type buffers_p: CTypesData
    """
    return buffers_p[0].avail_in


def _get_rs_buffers_t_unused_output_data_size(buffers_p: CTypesData) -> int:
    """Get the size of the unused output data buffer inside `rs_buffers_t`.

    :param buffers_p: The rs_buffers_t handle
    :type buffers_p: CTypesData
    """
    return buffers_p[0].avail_out


def _get_job_t_copy_arg(job_p: CTypesData) -> Any | None:  # noqa: ANN401
    """Get the python object referenced by the `((rs_job_t *)job_p)->copy_arg`.

    If this field is not set (i.e equals `_ffi.NULL`), None is returned.

    :param job_p: The job handle
    :type job_p: CTypesData
    :returns: The python object pointed to by the `copy_arg` field or None
    :returns: Union[Any, None]
    """
    if job_p[0].copy_arg != _ffi.NULL:
        return _ffi.from_handle(job_p[0].copy_arg)
    return None


def _get_sig_args(
    filesize: int = 0,
    sig_magic: int | RsSignatureMagic = 0,
    block_length: int = 0,
    hash_length: int = 0,
) -> tuple[RsSignatureMagic, int, int]:
    """Get recommended arguments for generating a file signature.

    :param filesize: The size of the file. Use 0 for "unknown".
    :type filesize: int
    :param sig_magic: The signature type. Use 0 for recommended.
    :type sig_magic: Union[int, RsSignatureMagic]
    :param block_length: The signature block length. Larger values make
    a shorter signature but increase the delta size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :returns: A 3-tuple containing the RsSignatureMagic, block_length and hash_length
    in that order.
    :rtype: tuple[RsSignatureMagic, int, int]
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    if sig_magic == 0:
        # Set the value the lib recommends, so that signature arg validation
        # can pass
        sig_magic = RsSignatureMagic.RK_BLAKE2_SIG

    _validate_sig_args(sig_magic, block_length, hash_length, get_sig_args_call=True)

    if filesize < 0:
        err = "Filesize must be >= 0"
        raise ValueError(err)

    sig_magic_p = _ffi.new("rs_magic_number *", sig_magic)
    block_length_p = _ffi.new("size_t *", block_length)
    if hash_length >= 0:
        hash_length_p = _ffi.new("size_t *", hash_length)
    else:
        hash_length_p = _ffi.new("size_t *", 2 ** (_ffi.sizeof("size_t") * 8) - 1)

    _handle_rs_result(
        _lib.rs_sig_args(filesize, sig_magic_p, block_length_p, hash_length_p),
        raise_on_non_error_results=False,
    )

    return RsSignatureMagic(sig_magic_p[0]), block_length_p[0], hash_length_p[0]


def _build_hash_table(sig_pp: CTypesData) -> None:
    """Index a signature after loading.

    When the signature handle is no longer needed, it must be deallocated with
    :meth:`free_sig`.

    :param sig_pp: The signature handle
    :type sig_pp: CTypesData
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    _validate_signature(sig_pp)
    _handle_rs_result(_lib.rs_build_hash_table(sig_pp[0]))


def _on_patch_copy_error(handle_name: str) -> Callable:
    """Handle exceptions raised while inside :meth:`_patch_copy_callback`.

    Set this function as the `onerror` handler inside the `_ffi.def_extern()`
    annotation of :meth:`_patch_copy_callback`:

    ```
    @_ffi.def_extern(onerror=_on_patch_copy_error('handle_arg_name'), ...)
    def _patch_copy_callback(
        # The patch handle. CTypesData reference to :class:`_PatchHandle`
        handle_arg_name: CTypesData,
        ...):
        ...
    ```

    This handler will derefence the :class:`_PatchHandle` instance passed to
    :meth:`_patch_copy_callback` method. If an exception is raised while inside
    the method, a reference to the exception instance will be saved under
    `_PatchHandle.exc` for processing after the patch iteration.

    :param handle_name: The name of the argument of :meth:`_patch_copy_callback`
    containing the CTypesData reference to :class:`_PatchHandle`.
    :type handle_name: str
    :returns: The onerror handler to be called by CFFI in an exception is raised
    while inside :meth:`_patch_copy_callback`
    :rtype: Callable
    """

    def _func(
        exception: type[BaseException] | None,  # noqa: ARG001
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Handle exceptions raised while inside :meth:`_patch_copy_callback`.

        :param exception: The type of the exception if one was raised
        :type exception: Optional[Type[BaseException]]
        :param exc_value: The instance of the exception if one was raised
        :type exc_value: Optional[BaseException]
        :param traceback: The traceback of the exception if one was raised
        :type traceback: Optional[TracebackType]
        """
        # See CFFI documentation on how this works:
        # <https://cffi.readthedocs.io/en/stable/using.html#extern-python-reference:~:text=onerror%3A%20if%20you,f_locals%5B%27argname%27%5D.>

        # Check an exception was raised and there is access to its traceback
        if traceback is not None and exc_value is not None:
            # Get the :meth:`_patch_copy_callback` frame
            callback_frame = traceback.tb_frame
            # Get the patch handle argument
            handle_p = callback_frame.f_locals[handle_name]
            # Get the patch handle instance
            patch_handle = cast(_PatchHandle, _ffi.from_handle(handle_p))
            # Save the exception instance inside the patch handle
            patch_handle.exc = exc_value

        # Always return None
        # This ensures CFFI will not print the exception traceback on stderr

    return _func


@_ffi.def_extern(
    error=RsResult.IO_ERROR,  # Return this from the callback if an exception is raised.
    onerror=_on_patch_copy_error("opaque_p"),  # Handle any raised exceptions
)
def _patch_copy_callback(
    opaque_p: CTypesData,  # Keep name in sync with the `onerror` handler above
    pos: int,
    len_p: CTypesData,
    buf_pp: CTypesData,
) -> RsResult:
    """Copy data from a basis file during a patching iteration.

    Invoked from the C API during a call to :meth:`job_iter` or
    :meth:`job_drive`.

    :param opaque_p: A pointer to the file-like python object
    :type opaque_p: CTypesData
    :param pos: Position where copying should begin
    :type pos: int
    :param len_p: A pointer to an integer type. On input, the amount of data
    that should be retrieved. Updated to show how much is actually available,
    but should not be greater than the input value.
    :type len_p: CTypesData
    :param buf_pp: A double pointer to a buffer of at least `len_p[0]` bytes.
    May be updated to point to another buffer holding the data if prefered.
    """
    patch_handle = cast(_PatchHandle, _ffi.from_handle(opaque_p))
    basis = patch_handle.basis

    for x in range(_MAX_COPY_OP_RETRIES + 1):
        try:
            # Read data from the basis
            basis.seek(pos)
            data = basis.read(len_p[0])
            break
        # Normally if `.seek()` or `.read()` raises an error, it should be
        # captured by CFFI and this callback should return `RsResult.IO_ERROR`
        # (the `error` and `onerror` arguments of the function annotation
        # ensure that).
        #
        # However, `BlockingIOError` is a special case, where the data is not
        # *yet* available. In this case there are 2 options:
        #   1. Block inside this callback to wait for the data. This will block
        #      the thread running :meth:`job_iter`.
        #   2. Return no data (len_p[0] == 0) and `RsResult.BLOCKED` or
        #      `RsResult.DONE`
        #
        # Option 2 sounds like the correct thing to do, however, due to librsync
        # implementation specifics it is not a viable option. See:
        # <https://github.com/librsync/librsync/issues/258>.
        #
        # This leaves only option 1.
        except BlockingIOError:
            if x < _MAX_COPY_OP_RETRIES:
                time.sleep(_SLEEP_DURATION_BETWEEN_COPY_OP_RETRIES)
            else:
                len_p[0] = 0
                raise  # Something is wrong. Give up.

    # Update the length with the actual read length
    len_p[0] = len(data)

    if len(data) == 0:
        return RsResult.INPUT_ENDED

    # Copy the data to the buffer
    c_buffer = _ffi.buffer(buf_pp[0], len(data))
    c_buffer[:] = data

    return RsResult.DONE


def _validate_sig_args(
    magic: RsSignatureMagic,
    block_length: int,
    hash_length: int,
    *,
    get_sig_args_call: bool = False,
) -> None:
    """Check that args for rs_sig_begin() or rs_get_sig_args() are valid.

    Replicates the `rs_sig_args_check()` macro.

    :param magic: The signature magic
    :type magic: RsSignatureMagic
    :param block_length: The signature block length
    :type block_length: int
    :param hash_length: The signature hash length
    :type hash_length: int
    :param get_sig_args_call: True if this is a call to `rs_get_sig_args()`
    :type get_sig_args_call:  bool
    :raises ValueError: If validation fails
    """
    err = ""

    max_hash_length = (
        _lib.RS_MD4_SUM_LENGTH
        if magic in (RsSignatureMagic.MD4_SIG, RsSignatureMagic.RK_MD4_SIG)
        else _lib.RS_BLAKE2_SUM_LENGTH
    )

    if magic not in iter(RsSignatureMagic):
        err = "Invalid signature magic."
    elif hash_length > max_hash_length:
        err = f"Signature hash length must be <={max_hash_length}"
    elif hash_length < (-1 if get_sig_args_call else 0):
        err = f"Signature hash length must be >={(-1 if get_sig_args_call else 0)}"
    elif block_length < 0:
        err = "Signature block length must be >0"

    if err:
        raise ValueError(err)


def _validate_signature(sig_pp: CTypesData) -> None:
    """Check that a signature is valid.

    Replicates the `rs_signature_check()` macro.

    :raises ValueError: If validation fails
    """
    err = ""
    sig = sig_pp[0][0]

    _validate_sig_args(sig.magic, sig.block_len, sig.strong_sum_len)

    if not (
        sig.count >= 0
        and sig.count <= sig.size
        and (sig.hashtable == _ffi.NULL or sig.hashtable.count <= sig.count)
    ):
        err = "Invalid signature."

    if err:
        raise ValueError(err)


def _validate_job(job_p: CTypesData) -> None:
    """Check that a job is valid.

    Replicates the `rs_job_check()` macro.

    :raises ValueError: If validation fails
    """
    err = ""
    job = job_p[0]

    if job.dogtag != 20010225:  # noqa: PLR2004
        err = "Invalid job."

    if err:
        raise ValueError(err)


def job_iter(
    job_p: CTypesData,
    input_: bytes,
    max_output_size: int = 0,
    *,
    eof: bool = False,
) -> tuple[RsResult, bytes, bytes]:
    """Run a single iteration of a given job.

    Calls `rs_job_iter` once and passes it the data inside the `input` buffer.

    After the call any remaining input data is returned alongside all of the
    produced output data.

    The result of the iteration is also returned. If the returned result is
    :class:`RsResult.DONE` no more iterations are necessary. However, a returned
    result of :class:`RsResult.BLOCKED` means one of 3 things:

    - More input data is needed. If there is no more input data call this
    function again with an empty input buffer and set the `eof` flag to `True`.
    - There is more output data to be returned.
    - Both of the above

    NOTE: The job_p handle must be deallocated with :meth:`free_job` when the
    result of the iteration is :class:`RsStatus.DONE` or the job and its results
    are no longer needed.

    :param input: The input buffer
    :type input: bytes
    :param max_output_size: The maximum size of the output data buffer. Set to `0`
    to use the same size as the input buffer (`len(input)`).
    :type max_output_size: int
    :param eof: True if this is the last input data from a given input stream.
    :type eof: bool
    :returns: The result of the iteration, the remaining input buffer data and
    the produced output data in that order
    :rtype: tuple[RsStatus, bytes, bytes]
    """
    _validate_job(job_p)

    if max_output_size == 0:
        max_output_size = len(input_)

    output = bytearray(max_output_size)
    buffers_p = _new_rs_buffers_t_p_handle(input_, output, eof=eof)

    try:
        result = _handle_rs_result(_lib.rs_job_iter(job_p, buffers_p))
    except RsCApiError as e:
        # Patch jobs (initialised with :meth:`patch_begin`) should have
        # this arg set to an instance of :class:`_PatchHandle`.
        copy_arg = cast(_PatchHandle | None, _get_job_t_copy_arg(job_p))
        # If an exception was raised while inside the :meth:`_patch_copy_callback`
        # the instance of that exception shuld be saved under `copy_arg.exc` by
        # the :meth:`_on_patch_copy_error` handler.
        if copy_arg and isinstance(copy_arg.exc, BaseException):
            raise copy_arg.exc from e
        raise

    unused_in_size = _get_rs_buffers_t_unused_input_data_size(buffers_p)
    unused_out_size = _get_rs_buffers_t_unused_output_data_size(buffers_p)

    return (
        result,
        input_[len(input_) - unused_in_size :],
        bytes(output[: (len(output) - unused_out_size)]),
    )


def free_job(job_p: CTypesData) -> None:
    """Free a job.

    :raises RsCApiError: If something goes wrong while inside the C API
    """
    try:
        _handle_rs_result(
            _lib.rs_job_free(job_p),
            raise_on_non_error_results=False,
        )
    finally:
        # Sanitise the pointers
        job_p = _ffi.NULL


def sig_begin(
    filesize: int = 0,
    sig_magic: int | RsSignatureMagic = 0,
    block_length: int = 0,
    hash_length: int = 0,
) -> CTypesData:
    """Start a signature generation.

    Returns a job handle, which must be passed to :meth:`job_iter` or
    :meth:`job_drive`.

    The job handle must be deallocated with :meth:`free_job` when no longer needed
    or the job completes.

    :param filesize: The size of the file.
    :type filesize: int
    :param sig_magic: The signature type. Use 0 for recommended.
    :type sig_magic: Union[int, RsSignatureMagic]
    :param block_length: The signature block length. Larger values make
    a shorter signature but increase the delta size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :returns: The job handle
    :rtype: CTypesData
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    sig_magic, block_length, hash_length = _get_sig_args(
        filesize,
        sig_magic,
        block_length,
        hash_length,
    )
    return _lib.rs_sig_begin(block_length, hash_length, sig_magic)


def loadsig_begin() -> tuple[CTypesData, CTypesData]:
    """Start loading a generated signature.

    Returns a signature handle and a job handle.

    The job handle must be passed to :meth:`job_iter` or
    :meth:`job_drive`.

    The job handle must be deallocated with :meth:`free_job` when no longer needed
    or the job completes.

    When the signature handle is no longer needed, it must be deallocated with
    :meth:`free_sig`.

    NOTE: The signature handle must not be used before the loadsig job has completed.

    :returns: The signature handle and the job handle in this order
    :rtype: tuple[CTypesData, CTypesData]
    """
    sig_pp = _new_rs_signature_t_pp_handle()
    return sig_pp, _lib.rs_loadsig_begin(sig_pp)


def free_sig(sig_pp: CTypesData) -> None:
    """Free a signature."""
    try:
        _lib.rs_free_sumset(sig_pp[0])  # Function returns void
    finally:
        # Sanitise the pointers
        sig_pp[0] = _ffi.NULL
        sig_pp = _ffi.NULL


def delta_begin(sig_pp: CTypesData) -> CTypesData:
    """Start a delta file generation.

    Returns a job handle, which must be passed to :meth:`job_iter` or
    :meth:`job_drive`.

    When the job completes, the signature handle must be deallocated with
    :meth:`free_sig` and the job handle must be deallocated with :meth:`free_job`.

    :param sig_pp: The signature handle
    :type sig_pp: CTypesData
    :returns: The job handle
    :rtype: CTypesData
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    # The signature must be indexed before use
    # _build_hash_table will also validate it
    _build_hash_table(sig_pp)
    return _lib.rs_delta_begin(sig_pp[0])


def get_delta_stats(sig_pp: CTypesData) -> MatchStats:
    """Get delta file generation statistics.

    :param sig_pp: The signature handle
    :type sig_pp: CTypesData
    :returns: The signature match statistics
    :rtype: MatchStats
    :raises NotImplementedError: If librsync was compiled without match
    statistics support
    """
    sig_p = sig_pp[0]

    if getattr(sig_p[0], "calc_strong_count", None) is None:
        err = "Librsync was compiled without `HASHTABLE_NSTATS` support."
        raise NotImplementedError(err)

    if sig_p[0].hashtable == _ffi.NULL:
        return MatchStats(
            find_count=0,
            match_count=0,
            hashcmp_count=0,
            entrycmp_count=0,
            strongsum_calc_count=0,
        )

    return MatchStats(
        find_count=sig_p[0].hashtable.find_count,
        match_count=sig_p[0].hashtable.match_count,
        hashcmp_count=sig_p[0].hashtable.hashcmp_count,
        entrycmp_count=sig_p[0].hashtable.entrycmp_count,
        strongsum_calc_count=sig_p[0].calc_strong_count,
    )


def patch_begin(basis: io.BufferedIOBase | io.RawIOBase) -> CTypesData:
    """Start a patched file generation.

    Returns a job handle, which must be passed to :meth:`job_iter` or
    :meth:`job_drive`.

    The job handle must be deallocated with :meth:`free_job` when no longer needed
    or the job completes.

    :param basis: A binary file-like object open for reading and supporting
    random access (`.seek()`).
    :type basis: Union[io.BufferedIOBase, io.RawIOBase]
    :returns: The job handle
    :rtype: CTypesData
    :raises ValueError: If there is something wrong with the provided arugments
    """
    patch_handle = _PatchHandle(basis)
    patch_handle_p = _ffi.new_handle(patch_handle)

    job_p = _lib.rs_patch_begin(
        # When the C API calls `_lib._patch_copy_callback`, the
        # :meth:`_patch_copy_callback` function will be called
        _lib._patch_copy_callback,  # noqa: SLF001
        patch_handle_p,
    )

    # Keep the handle alive until the job_p object is GCed
    _global_weakkeydict[job_p] = patch_handle_p

    return job_p


def get_job_stats(job_p: CTypesData) -> JobStats:
    """Get librsync job statistics.

    :param job_p: The job handle
    :type job_p: CTypesData
    :returns: The job statistics
    :rtype: JobStats
    """
    raw_stats = _lib.rs_job_statistics(job_p)

    if raw_stats.op != _ffi.NULL:
        job_type = cast(bytes, _ffi.buffer(raw_stats.op, 20)[:])
        job_type = job_type[: job_type.index(b"\x00")].decode()
    else:
        job_type = ""

    return JobStats(
        job_type=JobStats.JobType(job_type),
        lit_cmds=raw_stats.lit_cmds,
        lit_bytes=raw_stats.lit_bytes,
        lit_cmdbytes=raw_stats.lit_cmdbytes,
        copy_cmds=raw_stats.copy_cmds,
        copy_bytes=raw_stats.copy_bytes,
        copy_cmdbytes=raw_stats.copy_cmdbytes,
        sig_cmds=raw_stats.sig_cmds,
        sig_bytes=raw_stats.sig_bytes,
        false_matches=raw_stats.false_matches,
        sig_blocks=raw_stats.sig_blocks,
        block_len=raw_stats.block_len,
        in_bytes=raw_stats.in_bytes,
        out_bytes=raw_stats.out_bytes,
        start_time=datetime.fromtimestamp(raw_stats.start, timezone.utc),
        completion_time=(
            datetime.fromtimestamp(raw_stats.end, timezone.utc)
            if raw_stats.end
            else None
        ),
    )
