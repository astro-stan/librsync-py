# Copyright (c) 2024 librsync_py project. Released under AGPL-3.0
# license. Refer to the LICENSE file for details or visit:
# https://www.gnu.org/licenses/agpl-3.0.en.html
"""Librsync statistics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class JobType(str, Enum):
    """librsync job type."""

    NOOP = ""
    DELTA = "delta"
    PATCH = "patch"
    LOAD_SIGNATURE = "loadsig"
    SIGNATURE = "signature"


@dataclass(frozen=True)
class JobStatistics:
    """librsync job statistics."""

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
class MatchStatistics:
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
