# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html

from __future__ import annotations

import io
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, cast
from weakref import WeakKeyDictionary

from librsync_py.exceptions import RsCApiError

from . import RsResult, SignatureType, _ffi, _lib
from .common import handle_rs_result

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


@dataclass(frozen=True)
class JobStats:
    """librsync job statistics."""

    class JobType(str, Enum):
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
    def time_taken(self) -> int:
        """The amount of time taken to complete the job (in seconds).

        If the job has not completed yet, the time taken up to this point is
        returned.

        Due to C API limitations, the time will be rounded down to the last full
        second.
        """
        completion_time = self.completion_time or datetime.now(timezone.utc)
        return int((completion_time - self.start_time).total_seconds())

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


@dataclass(frozen=True)
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
        return float(self.hashcmp_count / (self.find_count or 1))

    @property
    def weaksumcmp_ratio(self) -> float:
        """The ratio of weak sum to total compares done."""
        return self.hashcmp_ratio

    @property
    def entrycmp_ratio(self) -> float:
        """The ratio of entry to total compares done."""
        return float(self.entrycmp_count / (self.find_count or 1))

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
        return float(self.match_count / (self.find_count or 1))

    @property
    def strongsum_calc_ratio(self) -> float:
        """The ratio of strong sum to total calculations done."""
        return float(self.strongsum_calc_count / (self.find_count or 1))


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
            err = "Expected a binary file-like object."
        elif self.basis.closed or not self.basis.readable():
            err = "Expected a file-like object that is open for reading."
        elif not self.basis.seekable():
            err = "Expected a file-like object which supports random access (.seek())."

        if err:
            raise OSError(err)

    def validate_exc(self) -> None:
        """Validate exc."""
        if not (self.exc is None or isinstance(self.exc, BaseException)):
            err = "Expected an instance of BaseException() or None"
            raise ValueError(err)


def _check_job_handle_valid(p_job_handle: CTypesData) -> None:
    """Validate a job handle.

    :param p_job_handle: The job handle to validate
    :type p_job_handle: CTypesData
    :raises ValueError: if the handle is not valid
    """
    if not (p_job_handle and p_job_handle != _ffi.NULL):
        err = "Invalid job handle."
        raise ValueError(err)


def _check_sig_handle_valid(pp_sig_handle: CTypesData) -> None:
    """Validate a signature handle.

    :param pp_sig_handle: The signature handle to validate
    :type pp_sig_handle: CTypesData
    :raises ValueError: if the handle is not valid
    """
    if not (
        pp_sig_handle and pp_sig_handle != _ffi.NULL and pp_sig_handle[0] != _ffi.NULL
    ):
        err = "Invalid signature handle."
        raise ValueError(err)


def _check_buffers_handle_valid(p_buffers_handle: CTypesData) -> None:
    """Validate a buffers handle.

    :param p_buffers_handle: The buffers handle to validate
    :type p_buffers_handle: CTypesData
    :raises ValueError: if the handle is not valid
    """
    if not (p_buffers_handle and p_buffers_handle != _ffi.NULL):
        err = "Invalid buffers handle."
        raise ValueError(err)


def _validate_sig_args(
    signature_type: SignatureType,
    block_length: int,
    hash_length: int,
    *,
    get_sig_args_call: bool = False,
) -> None:
    """Check that args for rs_sig_begin() or rs_get_sig_args() are valid.

    Replicates the `rs_sig_args_check()` macro.

    :param signature_type: The signature type
    :type signature_type: SignatureType
    :param block_length: The signature block length
    :type block_length: int
    :param hash_length: The signature hash length
    :type hash_length: int
    :param get_sig_args_call: True if this is for a call to `rs_get_sig_args()`
    :type get_sig_args_call:  bool
    :raises ValueError: If validation fails
    """
    err = ""

    max_hash_length = (
        _lib.RS_MD4_SUM_LENGTH
        if signature_type in (SignatureType.MD4_SIG, SignatureType.RK_MD4_SIG)
        else _lib.RS_BLAKE2_SUM_LENGTH
    )

    if signature_type not in iter(SignatureType):
        err = "Invalid signature type."
    elif hash_length > max_hash_length:
        err = f"Signature hash length must be <={max_hash_length}"
    elif hash_length < (-1 if get_sig_args_call else 0):
        err = f"Signature hash length must be >={(-1 if get_sig_args_call else 0)}"
    elif block_length < 0:
        err = "Signature block length must be >0"

    if err:
        raise ValueError(err)


def _validate_signature(pp_sig_handle: CTypesData) -> None:
    """Check that a signature is valid.

    Replicates the `rs_signature_check()` macro.

    :raises ValueError: If validation fails
    """
    _check_sig_handle_valid(pp_sig_handle)

    sig = pp_sig_handle[0][0]

    _validate_sig_args(sig.magic, sig.block_len, sig.strong_sum_len)

    if not (
        sig.count >= 0
        and sig.count <= sig.size
        and (sig.hashtable == _ffi.NULL or sig.hashtable.count <= sig.count)
    ):
        err = "Invalid signature."
        raise ValueError(err)


def _validate_job(p_job_handle: CTypesData) -> None:
    """Check that a job is valid.

    Replicates the `rs_job_check()` macro.

    :raises ValueError: If validation fails
    """
    _check_job_handle_valid(p_job_handle)

    if p_job_handle[0].dogtag != 20010225:  # noqa: PLR2004
        err = "Invalid job."
        raise ValueError(err)


def _new_rs_buffers_t_p_handle(
    input_: memoryview,
    output: memoryview,
    *,
    eof: bool = False,
) -> CTypesData:
    """Allocate a new rs_buffers_t handle.

    This handle will be automatically freed when no longer referenced.

    :param input_: The input buffer
    :type input_: memoryview
    :param output: The output buffer
    :type output: memoryview
    :param eof: True if this is the last input data from a given input stream.
    :type eof: bool
    :returns: The rs_buffers_t handle
    :rtype: CTypesData
    :raises ValueError: If memoryview objects do not represent a C char array.
    """
    err_explanation = (
        "buffer must repesent a single dimensional, contiguous memory "
        "region where each element is 1 byte long (i.e. a `char[]`)"
    )
    if input_.ndim != 1 or input_.itemsize != 1 or not input_.c_contiguous:
        err = f"input {err_explanation}"
        raise ValueError(err)
    if output.ndim != 1 or output.itemsize != 1 or not output.c_contiguous:
        err = f"output {err_explanation}"
        raise ValueError(err)

    p_buffers_handle = _ffi.new("rs_buffers_t *")

    p_in_buf = _ffi.from_buffer("char[]", input_, require_writable=False)
    p_buffers_handle[0].next_in = p_in_buf
    p_buffers_handle[0].avail_in = len(p_in_buf)

    p_out_buf = _ffi.from_buffer("char[]", output, require_writable=True)
    p_buffers_handle[0].next_out = p_out_buf
    p_buffers_handle[0].avail_out = len(p_out_buf)

    p_buffers_handle[0].eof_in = eof

    # Keep input and output buffers alive until the parent struct is GCed
    _global_weakkeydict[p_buffers_handle] = (p_in_buf, p_out_buf)

    return p_buffers_handle


def _new_rs_signature_t_pp_handle() -> CTypesData:
    """Allocate a new rs_signature_t handle.

    This handle will be automatically freed when no longer referenced.
    """
    return _ffi.new("rs_signature_t **")


def _get_rs_buffers_t_unused_input_data_size(p_buffers_handle: CTypesData) -> int:
    """Get the size of the unused intput data buffer inside `rs_buffers_t`.

    :param p_buffers_handle: The rs_buffers_t handle
    :type p_buffers_handle: CTypesData
    """
    _check_buffers_handle_valid(p_buffers_handle)
    return p_buffers_handle[0].avail_in


def _get_rs_buffers_t_unused_output_data_size(p_buffers_handle: CTypesData) -> int:
    """Get the size of the unused output data buffer inside `rs_buffers_t`.

    :param p_buffers_handle: The rs_buffers_t handle
    :type p_buffers_handle: CTypesData
    """
    _check_buffers_handle_valid(p_buffers_handle)
    return p_buffers_handle[0].avail_out


def _get_job_t_copy_arg(p_job_handle: CTypesData) -> Any | None:  # noqa: ANN401
    """Get the python object referenced by the `((rs_job_t *)p_job_handle)->copy_arg`.

    If this field is not set (i.e equals `_ffi.NULL`), None is returned.

    :param p_job_handle: The job handle
    :type p_job_handle: CTypesData
    :returns: The python object pointed to by the `copy_arg` field or None
    :returns: Union[Any, None]
    """
    _validate_job(p_job_handle)
    if p_job_handle[0].copy_arg != _ffi.NULL:
        return _ffi.from_handle(p_job_handle[0].copy_arg)
    return None


def _get_sig_args(
    filesize: int = -1,
    signature_type: int | SignatureType = 0,
    block_length: int = 0,
    hash_length: int = 0,
) -> tuple[SignatureType, int, int]:
    """Get recommended arguments for generating a file signature.

    :param filesize: The size of the file. Use -1 for "unknown".
    :type filesize: int
    :param signature_type: The signature type. Use 0 for recommended.
    :type signature_type: Union[int, SignatureType]
    :param block_length: The signature block length. Larger values make
    a shorter signature but increase the delta size. Use 0 for recommended.
    :type block_length: int
    :param hash_length: The signature hash (strongsum) length. Smaller values
    make signatures shorter but increase the chance for corruption due to
    hash collisions. Use `0` for maximum or `-1` for minimum.
    :returns: A 3-tuple containing the SignatureType, block_length and hash_length
    in that order.
    :rtype: tuple[SignatureType, int, int]
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    if signature_type == 0:
        # Set the value the lib recommends, so that signature arg validation
        # can pass
        signature_type = SignatureType.RK_BLAKE2_SIG

    _validate_sig_args(
        signature_type,
        block_length,
        hash_length,
        get_sig_args_call=True,
    )

    # -1 is allowed, as it means "unknown"
    if filesize < -1:
        err = "Filesize must be >= 0"
        raise ValueError(err)

    p_sig_magic = _ffi.new("rs_magic_number *", signature_type)
    p_block_length = _ffi.new("size_t *", block_length)
    if hash_length >= 0:
        p_hash_length = _ffi.new("size_t *", hash_length)
    else:
        p_hash_length = _ffi.new("size_t *", 2 ** (_ffi.sizeof("size_t") * 8) - 1)

    handle_rs_result(
        _lib.rs_sig_args(filesize, p_sig_magic, p_block_length, p_hash_length),
        raise_on_non_error_results=False,
    )

    return SignatureType(p_sig_magic[0]), p_block_length[0], p_hash_length[0]


def build_hash_table(pp_sig_handle: CTypesData) -> None:
    """Index a signature after loading.

    Must be called on a signature after the load signature job (created with
    :meth:`loadsig_begin`) has been passed to :meth:`job_iter` and the job
    has completed.

    When the signature handle is no longer needed, it must be deallocated with
    :meth:`free_sig`.

    :param pp_sig_handle: The signature handle
    :type pp_sig_handle: CTypesData
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    _validate_signature(pp_sig_handle)
    handle_rs_result(_lib.rs_build_hash_table(pp_sig_handle[0]))


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
            p_handle = callback_frame.f_locals[handle_name]
            # Get the patch handle instance
            patch_handle = cast(_PatchHandle, _ffi.from_handle(p_handle))
            # Save the exception instance inside the patch handle
            patch_handle.exc = exc_value

        # Always return None
        # This ensures CFFI will not print the exception traceback on stderr

    return _func


@_ffi.def_extern(
    error=RsResult.IO_ERROR,  # Return this from the callback if an exception is raised.
    onerror=_on_patch_copy_error("p_opaque"),  # Handle any raised exceptions
)
def _patch_copy_callback(
    p_opaque: CTypesData,  # Keep name in sync with the `onerror` handler above
    pos: int,
    p_len: CTypesData,
    pp_buf: CTypesData,
) -> RsResult:
    """Copy data from a basis file during a patching iteration.

    Invoked from the C API during a call to :meth:`job_iter`.

    :param p_opaque: A pointer to the file-like python object
    :type p_opaque: CTypesData
    :param pos: Position where copying should begin
    :type pos: int
    :param p_len: A pointer to an integer type. On input, the amount of data
    that should be retrieved. Updated to show how much is actually available,
    but should not be greater than the input value.
    :type p_len: CTypesData
    :param pp_buf: A double pointer to a buffer of at least `p_len[0]` bytes.
    May be updated to point to another buffer holding the data if prefered.
    :type pp_buf: CTypesData
    """
    patch_handle = cast(_PatchHandle, _ffi.from_handle(p_opaque))
    basis = patch_handle.basis

    for x in range(_MAX_COPY_OP_RETRIES + 1):
        try:
            # Read data from the basis
            basis.seek(pos)
            data = basis.read(p_len[0])
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
        #   2. Return no data (p_len[0] == 0) and `RsResult.BLOCKED` or
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
                p_len[0] = 0
                raise  # Something is wrong. Give up.

    # Update the length with the actual read length
    p_len[0] = len(data)

    if len(data) == 0:
        return RsResult.INPUT_ENDED

    # Copy the data to the buffer
    c_buffer = _ffi.buffer(pp_buf[0], len(data))
    c_buffer[:] = data

    return RsResult.DONE


def job_iter(
    p_job_handle: CTypesData,
    input_: memoryview,
    output: memoryview,
    *,
    eof: bool = False,
) -> tuple[RsResult, int, int]:
    """Run a single iteration of a given job.

    Calls `rs_job_iter` once and passes it the data inside the `input_` buffer.

    The produced output is stored inside the `output` buffer.

    The result of the iteration is returned along with the consumed input length
    and produced output length.

    If the returned result is :class:`RsResult.DONE` no more iterations are
    necessary and the job has completed. However, a returned result of
    :class:`RsResult.BLOCKED` means one of 3 things:

    - More input data is needed. If there is no more input data call this
    function again with an empty input buffer and set the `eof` flag to `True`.
    - There is more output data to be returned. NOTE: The output buffer may be
      too small. Try again with a larger buffer if you keep getting this result.
    - Both of the above

    NOTE: The p_job_handle handle must be deallocated with :meth:`free_job` when the
    result of the iteration is :class:`RsStatus.DONE` or the job and its results
    are no longer needed.

    :param p_job_handle: The job handle
    :type p_job_handle: CTypesData
    :param input_: The input buffer
    :type input_: memoryview
    :param output: The output buffer
    :type output: memoryview
    :param eof: True if this is the last input data from a given input stream.
    :type eof: bool
    :returns: The result of the iteration, the length of the consumed input
    and the length of the produced output in this order
    :rtype: tuple[RsStatus, int, int]
    :raises ValueError: If argument validation fails
    """
    _validate_job(p_job_handle)

    p_buffers_handle = _new_rs_buffers_t_p_handle(input_, output, eof=eof)

    try:
        result = handle_rs_result(_lib.rs_job_iter(p_job_handle, p_buffers_handle))
    except RsCApiError as e:
        # Patch jobs (initialised with :meth:`patch_begin`) should have
        # this arg set to an instance of :class:`_PatchHandle`.
        copy_arg = cast(_PatchHandle | None, _get_job_t_copy_arg(p_job_handle))
        # If an exception was raised while inside the :meth:`_patch_copy_callback`
        # the instance of that exception shuld be saved under `copy_arg.exc` by
        # the :meth:`_on_patch_copy_error` handler.
        if copy_arg and isinstance(copy_arg.exc, BaseException):
            raise copy_arg.exc from e
        raise

    return (
        result,
        len(input_) - _get_rs_buffers_t_unused_input_data_size(p_buffers_handle),
        len(output) - _get_rs_buffers_t_unused_output_data_size(p_buffers_handle),
    )


def free_job(p_job_handle: CTypesData) -> None:
    """Free a job.

    :raises RsCApiError: If something goes wrong while inside the C API
    """
    _check_job_handle_valid(p_job_handle)

    try:
        handle_rs_result(
            _lib.rs_job_free(p_job_handle),
            raise_on_non_error_results=False,
        )
    finally:
        # Sanitise the pointers
        p_job_handle = _ffi.NULL


def sig_begin(
    filesize: int = -1,
    signature_type: int | SignatureType = 0,
    block_length: int = 0,
    hash_length: int = 0,
) -> CTypesData:
    """Start a signature generation.

    Returns a job handle, which must be passed to :meth:`job_iter`.

    The job handle must be deallocated with :meth:`free_job` when no longer needed
    or the job completes.

    :param filesize: The size of the file. Use -1 for "unknown"
    :type filesize: int
    :param signature_type: The signature type. Use 0 for recommended.
    :type signature_type: Union[int, SignatureType]
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
    signature_type, block_length, hash_length = _get_sig_args(
        filesize,
        signature_type,
        block_length,
        hash_length,
    )
    return _lib.rs_sig_begin(block_length, hash_length, signature_type)


def loadsig_begin() -> tuple[CTypesData, CTypesData]:
    """Start loading a generated signature.

    Returns a signature handle and a job handle.

    The job handle must be passed to :meth:`job_iter`.

    The job handle must be deallocated with :meth:`free_job` when no longer needed
    or the job completes.

    When the signature handle is no longer needed, it must be deallocated with
    :meth:`free_sig`.

    NOTE: The signature handle must not be used before the loadsig job has completed.

    :returns: The signature handle and the job handle in this order
    :rtype: tuple[CTypesData, CTypesData]
    """
    pp_sig_handle = _new_rs_signature_t_pp_handle()
    return pp_sig_handle, _lib.rs_loadsig_begin(pp_sig_handle)


def free_sig(pp_sig_handle: CTypesData) -> None:
    """Free a signature."""
    _check_sig_handle_valid(pp_sig_handle)

    try:
        _lib.rs_free_sumset(pp_sig_handle[0])  # Function returns void
    finally:
        # Sanitise the pointers
        pp_sig_handle[0] = _ffi.NULL
        pp_sig_handle = _ffi.NULL


def delta_begin(pp_sig_handle: CTypesData) -> CTypesData:
    """Start a delta file generation.

    Returns a job handle, which must be passed to :meth:`job_iter`.

    When the job completes, the signature handle must be deallocated with
    :meth:`free_sig` and the job handle must be deallocated with :meth:`free_job`.

    :param pp_sig_handle: The signature handle. The signature must have first been
    indexed with :meth:`build_hash_table`.
    :type pp_sig_handle: CTypesData
    :returns: The job handle
    :rtype: CTypesData
    :raises RsCApiError: If something goes wrong while inside the C API
    """
    # Purposefully only check the handle is valid here
    # since the signature might not be fully loaded  or indexed yet.
    # I.e. loadsig job might have not completed or
    # the signature might not have been indexed yet.
    _check_sig_handle_valid(pp_sig_handle)
    return _lib.rs_delta_begin(pp_sig_handle[0])


def get_match_stats(pp_sig_handle: CTypesData) -> MatchStats:
    """Get delta file generation statistics.

    :param pp_sig_handle: The signature handle
    :type pp_sig_handle: CTypesData
    :returns: The signature match statistics
    :rtype: MatchStats
    :raises NotImplementedError: If librsync was compiled without match
    statistics support
    """
    _validate_signature(pp_sig_handle)

    p_sig = pp_sig_handle[0]

    if getattr(p_sig[0], "calc_strong_count", None) is None:
        err = "Librsync was compiled without `HASHTABLE_NSTATS` support."
        raise NotImplementedError(err)

    if p_sig[0].hashtable == _ffi.NULL:
        return MatchStats(
            find_count=0,
            match_count=0,
            hashcmp_count=0,
            entrycmp_count=0,
            strongsum_calc_count=0,
        )

    return MatchStats(
        find_count=p_sig[0].hashtable.find_count,
        match_count=p_sig[0].hashtable.match_count,
        hashcmp_count=p_sig[0].hashtable.hashcmp_count,
        entrycmp_count=p_sig[0].hashtable.entrycmp_count,
        strongsum_calc_count=p_sig[0].calc_strong_count,
    )


def patch_begin(basis: io.BufferedIOBase | io.RawIOBase) -> CTypesData:
    """Start a patched file generation.

    Returns a job handle, which must be passed to :meth:`job_iter`.

    The job handle must be deallocated with :meth:`free_job` when no longer needed
    or the job completes.

    :param basis: A binary file-like object open for reading and supporting
    random access (`.seek()`).
    :type basis: Union[io.BufferedIOBase, io.RawIOBase]
    :returns: The job handle
    :rtype: CTypesData
    :raises ValueError: If there is something wrong with the provided arugments
    :raises OSError: If there is something wrong with the provided arugments
    """
    patch_handle = _PatchHandle(basis)
    p_patch_handle = _ffi.new_handle(patch_handle)

    p_job_handle = _lib.rs_patch_begin(
        # When the C API calls `_lib._patch_copy_callback`, the
        # :meth:`_patch_copy_callback` function will be called
        _lib._patch_copy_callback,  # noqa: SLF001
        p_patch_handle,
    )

    # Keep the handle alive until the p_job_handle object is GCed
    _global_weakkeydict[p_job_handle] = p_patch_handle

    return p_job_handle


def get_job_stats(
    p_job_handle: CTypesData,
    in_bytes: int,
    out_bytes: int,
) -> JobStats:
    """Get librsync job statistics.

    The in and out bytes are needed due to a C API limitation, where those
    statistics are not updated when not using whole API.

    :param p_job_handle: The job handle
    :type p_job_handle: CTypesData
    :param in_bytes: The total input bytes. Must be >= 0.
    :type in_bytes: int
    :param out_bytes: The total output bytes. Must be >= 0.
    :type out_bytes: int
    :returns: The job statistics
    :rtype: JobStats
    """
    _validate_job(p_job_handle)

    raw_stats = _lib.rs_job_statistics(p_job_handle)

    if raw_stats.op != _ffi.NULL:
        job_type = cast(bytes, _ffi.buffer(raw_stats.op, 20)[:])
        job_type = job_type[: job_type.index(b"\x00")].decode()
    else:
        job_type = ""

    msg = "{} must be >= 0"
    if in_bytes < 0:
        raise ValueError(msg.format("in_bytes"))
    if out_bytes < 0:
        raise ValueError(msg.format("out_bytes"))

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
        in_bytes=in_bytes,
        out_bytes=out_bytes,
        start_time=datetime.fromtimestamp(raw_stats.start, timezone.utc),
        completion_time=(
            datetime.fromtimestamp(raw_stats.end, timezone.utc)
            if raw_stats.end
            else None
        ),
    )


def get_lib_version_str() -> str:
    """Get librsync version string."""
    version = cast(bytes, _ffi.buffer(_lib.rs_librsync_version, 20)[:])
    return version[: version.index(b"\x00")].decode()
