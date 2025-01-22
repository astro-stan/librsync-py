# librsync-py

<img src="https://img.shields.io/github/actions/workflow/status/astro-stan/librsync-py/.github%2Fworkflows%2Fbuild-and-run-tests.yml?branch=main&logo=github" alt="Build Status"> <a href="https://codecov.io/gh/astro-stan/librsync-py" ><img src="https://codecov.io/gh/astro-stan/librsync-py/graph/badge.svg"/></a> <a href="https://github.com/astro-stan/librsync-py/releases/latest"><img src="https://img.shields.io/github/v/release/astro-stan/librsync-py" alt="Latest GitHub Release"></a> <a href="./LICENSE"><img src="https://img.shields.io/github/license/astro-stan/librsync-py" alt="License AGPL-3.0"></a>

Python bindings for the [librsync library](https://github.com/librsync/librsync).

## Table Of Contents

* [Features](#features)
* [Getting Started](#getting-started)
    + [Prerequisites](#prerequisites)
    + [Usage Examples](#usage-examples)
* [Contributing](#contributing)
* [Reporting Vulnerabilities](#reporting-vulnerabilities)

## Features

* Thread-safe
* Exposes `librsync`'s "[Streaming API](https://librsync.github.io/api_streaming.html)"
  through buffereded binary streams, which inherit from
  [`BufferedIOBase`](https://docs.python.org/3/library/io.html#io.BufferedIOBase)
  and provide high-level access to readable, non seekable
  [`RawIOBase`](https://docs.python.org/3/library/io.html#io.RawIOBase)/
  [`BytesIO`](https://docs.python.org/3/library/io.html#io.BytesIO)
  raw binary streams, processing the data on the fly.
* Simulates `librsync`'s "[Whole-file API](https://librsync.github.io/api_whole.html)"
  by exposing high-level one-shot functions for processing data.
* Exposes `librsync`'s statistics API through dataclasses.

## Getting Started

### Prerequisites

Download and install the wheels/sdist from [PyPI](https://pypi.org/project/librsync-py/) or [GitHub](https://github.com/astro-stan/librsync-py/releases).

### Usage Examples

Here are some usage examples:

```py
from librsync_py import Signature, Delta, Patch, signature, delta, patch, LIBRSYNC_VERSION_STR, SignatureType

print(LIBRSYNC_VERSION_STR) # "librsync x.x.x"

A = b"12345"
B = b"1234"

# Whole API

sig_A = signature(A)
print(sig_A)

delta_B = delta(sig_A, B)
print(delta_B)

updated_A = patch(A, delta_B)
print(updated_A)

if updated_A == B:
    print("yay!")
else:
    print("nay")

# Streaming API

sig_A = Signature(
    # Also accepts in-memory file-like objects such as `io.BytesIO(b"123")`
    open("A", 'rb'),
    # All args below are optional
    # 32 KiB. Larger buffers generally improve performance
    buffer_size=32 * 1024,
    # The total size of the input data (if known in advance, None otherwise)
    file_size=...,
    # This is the default signature type when not specified
    signature_type=SignatureType.RK_BLAKE2,
    # The signature block length. Larger values make a shorter signature but
    # increase the delta file size. Use 0 to determine automatically.
    block_length=...,
    # The signature hash (strongsum) length. Smaller values make signatures
    # shorter but increase the chance for corruption due to hash collisions.
    # Use `0` for maximum (default) or `-1` for minimum.
    hash_length=...
)

delta_B = Delta(
    # Also accepts in memory file-like objects such as `io.BytesIO(sig_A.read())`
    sig_A,
    open("B", 'rb'),
    buffer_size=32 * 1024
)

# Load the signature
delta_B.load_signature(10) # Load up to 10 bytes
delta_B.load_signature() # Load the rest

# NOTE: The full signature needs to be in memory before we proceed
print(delta_B.signature_loaded) # True

# Print statistics:
print(sig_A.job_stats)
print(delta_B.job_stats)
print(delta_B.signature_job_stats)
print(delta_B.match_stats)

# Close the signature stream as it is no longer needed
sig_A.close() # Alternatively use: delta_B.close_signature()

updated_A = Patch(
    open("A", 'rb'),
    delta_B,
    buffer_size=32 * 1024
)

with open("updated_A", 'wb') as f:
    # Output can also be written in chunks by providing read with a maximum
    # read size. For example: `updated_A.read(256)` will read up to 256 bytes
    f.write(updated_A.read())

# Print statistics:
print(updated_A.job_stats)

# Close the streams as they are not longer needed
delta_B.close() # Alternatively use: updated_A.close()
updated_A.close_basis() # Close `open("A", 'rb')`
```

## Contributing

See [CONTRIBUTING.md](https://github.com/astro-stan/librsync-py/blob/main/CONTRIBUTING.md).

## Reporting Vulnerabilities

> :warning: **NEVER** open public issues or pull requests to report or fix security vulnerabilities.

See the [Security Policy](https://github.com/astro-stan/librsync-py/blob/main/SECURITY.md).
