from __future__ import annotations

import argparse
from pathlib import Path

from sentinel.bloom import BloomFilter
from sentinel.signatures import iter_signature_hashes, load_json_signatures, write_sqlite_database


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = PROJECT_ROOT / "data" / "signatures.json"
DEFAULT_SQLITE = PROJECT_ROOT / "data" / "signatures.db"
DEFAULT_BLOOM = PROJECT_ROOT / "data" / "filter.bloom"


def build_database(
    source: str | Path = DEFAULT_SOURCE,
    sqlite_output: str | Path = DEFAULT_SQLITE,
    bloom_output: str | Path = DEFAULT_BLOOM,
    false_positive_rate: float = 0.01,
) -> tuple[int, int]:
    signatures = load_json_signatures(source)
    hashes = list(iter_signature_hashes(signatures))

    bloom = BloomFilter.create(expected_items=len(hashes), false_positive_rate=false_positive_rate)
    for digest in hashes:
        bloom.add(digest)

    write_sqlite_database(signatures, sqlite_output)
    bloom.save(bloom_output)
    return len(signatures), len(hashes)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Sentinel SQLite and Bloom filter files.")
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="source JSON signature file")
    parser.add_argument("--db", default=str(DEFAULT_SQLITE), help="output SQLite database path")
    parser.add_argument("--bloom", default=str(DEFAULT_BLOOM), help="output Bloom filter path")
    parser.add_argument(
        "--false-positive-rate",
        type=float,
        default=0.01,
        help="target Bloom filter false positive rate",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    signature_count, hash_count = build_database(
        source=args.source,
        sqlite_output=args.db,
        bloom_output=args.bloom,
        false_positive_rate=args.false_positive_rate,
    )
    print(f"Loaded signatures: {signature_count}")
    print(f"Bloom hash entries: {hash_count}")
    print(f"SQLite database: {Path(args.db).resolve()}")
    print(f"Bloom filter: {Path(args.bloom).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
