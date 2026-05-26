# Sentinel Virus Scanner

Sentinel is a classroom-safe Python CLI virus scanner. The advanced version uses
an on-disk SQLite signature database plus an in-memory Bloom filter, threaded
file scanning, chunked hashing, streaming hex-pattern checks, PE Import Address
Table heuristics, Shannon entropy heuristics, and JSON/text reporting.

## Project Structure

- `build_db.py`: builds `data/signatures.db` and `data/filter.bloom` from `data/signatures.json`.
- `sentinel/`: scanner package, CLI, Bloom filter, SQLite lookup, scanning engine, and heuristics.
- `data/signatures.json`: editable source signature list.
- `data/signatures.db`: generated SQLite signature database.
- `data/filter.bloom`: generated serialized Bloom filter.
- `samples/demo/`: clean, EICAR, mock pattern, and entropy demo samples.
- `reports/`: generated scan reports.
- `tests/`: unit tests for the required scenarios.

## Build The Hybrid Database

Run from the `Project1` directory:

```bash
python3 build_db.py
```

This reads `data/signatures.json`, creates the indexed SQLite database, and
serializes the Bloom filter. The scanner loads only the `.bloom` file into
memory at startup; SQLite records are queried from disk only when needed.

## Quick Start

```bash
python3 -m sentinel scan samples/demo --db data/signatures.db --bloom data/filter.bloom --report reports/scan.json --text-report reports/scan.txt --benchmark
```

Expected demo detections:

- EICAR test file: `Signature` via Bloom-filter hash pre-check, SQLite lookup, and hex pattern.
- `MALWARE_SIMULATION_PAYLOAD`: `Signature` via streaming hex-pattern matching.
- `high_entropy.bin`: `Heuristic_Entropy` via Shannon entropy.

## CLI

```bash
python3 -m sentinel scan <target> --db data/signatures.db --bloom data/filter.bloom --report reports/scan.json
```

Useful options:

- `--workers N`: set the number of scan workers.
- `--executor thread|process`: choose ThreadPoolExecutor or ProcessPoolExecutor.
- `--benchmark`: print total time, files/sec, and MB/s.
- `--text-report reports/scan.txt`: also write a plain-text report.
- `--no-heuristics`: disable PE IAT and entropy heuristics.
- `--no-patterns`: disable streaming hex-pattern checks.

## Advanced Design Notes

Hash signatures use a two-tier lookup:

1. Check the file MD5/SHA-256 against the in-memory Bloom filter.
2. Query SQLite only after a Bloom hit. If SQLite has no matching row, the hit is treated as a Bloom false positive.

File hashing, entropy calculation, and pattern checks use 8 KB chunks, so large
files are not loaded into memory. Symbolic links are skipped to avoid traversal
loops, and permission or I/O errors are recorded as warnings without stopping
the scan.

PE heuristic analysis uses the optional `pefile` package. If `pefile` is not
installed, PE IAT analysis is skipped with a warning, while entropy and
signature scanning still work.

## Tests

```bash
python3 -m unittest discover tests
```

The tests cover database building, Bloom/SQLite signature lookup, hex-pattern
matching, entropy heuristic detection, mocked PE IAT detection, empty files,
symlink skipping, and report fields.

## Safety

The demo uses the EICAR antivirus test string and harmless mock data only. Do
not add real malware samples to this project.
