# Copyright (c) 2024-2025 librsync-py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Tests for the whole API."""

import io

from librsync_py import SignatureType, delta, patch, signature


def test_signature() -> None:
    """Test getting a signature."""
    data = b"123" * 100

    def assert_result(result: bytes, signature: SignatureType) -> None:
        assert isinstance(result, bytes)
        assert len(result) > 0
        assert result.startswith(signature.to_bytes(4, "big"))

    assert_result(signature(data), SignatureType.RK_BLAKE2)
    assert_result(signature(data, sig_type=SignatureType.MD4), SignatureType.MD4)
    assert_result(signature(io.BytesIO(data)), SignatureType.RK_BLAKE2)
    assert_result(
        signature(io.BytesIO(data), sig_type=SignatureType.MD4),
        SignatureType.MD4,
    )


def test_delta() -> None:
    """Test getting a delta."""
    data = b"123" * 100
    old_data = b"432" * 123

    def assert_result(result: bytes) -> None:
        assert isinstance(result, bytes)
        assert len(result) > 0

    assert_result(delta(signature(old_data), data))
    assert_result(delta(io.BytesIO(signature(io.BytesIO(old_data))), io.BytesIO(data)))


def test_patch() -> None:
    """Test patching data."""
    data = b"123" * 100
    old_data = b"432" * 123

    def assert_result(result: bytes) -> None:
        assert isinstance(result, bytes)
        assert len(result) > 0
        assert result == data

    assert_result(patch(old_data, delta(signature(old_data), data)))
    assert_result(
        patch(
            io.BytesIO(old_data),
            delta(io.BytesIO(signature(io.BytesIO(old_data))), io.BytesIO(data)),
        )
    )
