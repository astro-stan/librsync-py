# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Tests of the exception classes."""

from librsync_py import RsSignatureMagic, delta, patch, signature


def test_signature() -> None:
    """Test getting a signature."""
    data = b"123" * 100

    def assert_result(result: bytes, signature: RsSignatureMagic) -> None:
        assert isinstance(result, bytes)
        assert len(result) > 0
        assert result.startswith(signature.to_bytes(4, "big"))

    assert_result(signature(data), RsSignatureMagic.RK_BLAKE2_SIG)
    assert_result(
        signature(data, sig_type=RsSignatureMagic.MD4_SIG),
        RsSignatureMagic.MD4_SIG,
    )


def test_delta() -> None:
    """Test getting a delta."""
    data = b"123" * 100
    old_data = b"432" * 123

    result = delta(signature(old_data), data)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_patch() -> None:
    """Test patching data."""
    data = b"123" * 100
    old_data = b"432" * 123

    result = patch(old_data, delta(signature(old_data), data))
    assert isinstance(result, bytes)
    assert len(result) > 0
    assert result == data
