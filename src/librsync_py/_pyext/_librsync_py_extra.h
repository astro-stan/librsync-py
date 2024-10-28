/**
 * @file _librsync_py_extra.h
 * @brief Extra pyext defintions. This file is directly parsed by CFFI
 *
 * @copyright Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
 * license. Refer to the LICENSE file for details or visit:
 * https://www.gnu.org/licenses/agpl-3.0.en.html
 *
 */
extern "Python" {

/**
 * A generic copy callback corresponding to `rs_copy_cb` defined in `librsync.h`
 *
 * Calling this function will result in execution of a python
 * function annotated with
 * `@ffi.def_extern(name='_patch_copy_callback')`
 *
 * @param opaque A python object to be passed as context
 * @param pos Position where copying should begin
 * @param len On input, the amount of data that should be retrieved. Updated to
 * show how much is actually available, but should not be greater than the
 * input value.
 * @param buf On input, a buffer of at least \p *len bytes. May be updated to
 * point to a buffer allocated by the callback if preferred.
 * @return `rs_result` The result of the operation
 * @retval `RS_DONE` on success
 */
rs_result _patch_copy_callback(
    void *opaque,
    rs_long_t pos,
    size_t *len,
    void **buf);

}
