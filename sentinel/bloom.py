from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import struct


MAGIC = b"SNTBLM1\0"
HEADER = struct.Struct("!II")


@dataclass
class BloomFilter:
    """Small dependency-free Bloom filter for signature hash pre-checks."""

    size_bits: int
    hash_count: int
    bits: bytearray

    @classmethod
    def create(cls, expected_items: int, false_positive_rate: float = 0.01) -> "BloomFilter":
        if expected_items < 1:
            expected_items = 1
        if not 0 < false_positive_rate < 1:
            raise ValueError("false_positive_rate must be between 0 and 1")

        size_bits = int(
            -(expected_items * math.log(false_positive_rate)) / (math.log(2) ** 2)
        )
        size_bits = max(size_bits, 8)
        hash_count = max(1, int(round((size_bits / expected_items) * math.log(2))))
        return cls(size_bits=size_bits, hash_count=hash_count, bits=bytearray((size_bits + 7) // 8))

    def add(self, item: str) -> None:
        for position in self._positions(item):
            self.bits[position // 8] |= 1 << (position % 8)

    def might_contain(self, item: str | None) -> bool:
        if not item:
            return False
        return all(self.bits[position // 8] & (1 << (position % 8)) for position in self._positions(item))

    def save(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("wb") as handle:
            handle.write(MAGIC)
            handle.write(HEADER.pack(self.size_bits, self.hash_count))
            handle.write(bytes(self.bits))

    @classmethod
    def load(cls, path: str | Path) -> "BloomFilter":
        with Path(path).open("rb") as handle:
            magic = handle.read(len(MAGIC))
            if magic != MAGIC:
                raise ValueError("invalid Bloom filter file")

            raw_header = handle.read(HEADER.size)
            if len(raw_header) != HEADER.size:
                raise ValueError("truncated Bloom filter header")

            size_bits, hash_count = HEADER.unpack(raw_header)
            bits = bytearray(handle.read())

        expected_bytes = (size_bits + 7) // 8
        if len(bits) != expected_bytes:
            raise ValueError("Bloom filter bit array has an unexpected size")
        if hash_count < 1:
            raise ValueError("Bloom filter hash_count must be positive")

        return cls(size_bits=size_bits, hash_count=hash_count, bits=bits)

    def _positions(self, item: str) -> list[int]:
        normalized = item.strip().lower().encode("utf-8")
        positions: list[int] = []

        for seed in range(self.hash_count):
            digest = hashlib.sha256(seed.to_bytes(4, "big") + normalized).digest()
            positions.append(int.from_bytes(digest[:8], "big") % self.size_bits)

        return positions
