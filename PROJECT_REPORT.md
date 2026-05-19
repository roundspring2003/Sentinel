# Sentinel Virus Scanner Project Report

## Overview

Sentinel is a defensive Python CLI virus scanner. It recursively scans a target
file or directory, computes MD5 and SHA-256 hashes using chunks, performs a
Bloom-filter pre-check, queries an indexed SQLite signature database only when
necessary, streams hex-pattern checks, applies PE/entropy heuristics, and writes
JSON or text reports. It never executes scanned files.

## Hybrid Signature Database

The editable source remains `data/signatures.json`, but runtime scanning uses
two generated artifacts:

- `data/signatures.db`: SQLite database containing `id`, `name`, `severity`, `md5`, `sha256`, `hex_pattern`, and `description`.
- `data/filter.bloom`: serialized Bloom filter containing known MD5/SHA-256 values.

`build_db.py` validates the JSON, creates the SQLite table, adds indexes for
`md5` and `sha256`, and serializes the Bloom filter. At scanner startup, only
the Bloom filter is loaded into memory. Full signature metadata stays on disk
and is queried lazily through SQLite.

The lookup flow is:

1. Calculate file MD5/SHA-256 in 8 KB chunks.
2. Check each digest against the in-memory Bloom filter.
3. If Bloom misses, skip SQLite hash lookup.
4. If Bloom hits, query SQLite by indexed hash.
5. If SQLite has no row, treat the Bloom hit as a false positive.

This design reduces memory use compared with loading the full JSON signature
list into Python dictionaries.

## Scanning Engine And Edge Cases

The scanner uses `ThreadPoolExecutor` for concurrent file scanning. Each worker
reads files in 8 KB chunks, so a large file can be hashed and analyzed without
loading the entire file into RAM. During the same streaming pass, Sentinel also
updates byte-frequency counts for entropy calculation and checks hex-pattern
signatures with chunk overlap.

Defensive behavior includes:

- Symbolic links are skipped to avoid recursive link loops.
- `PermissionError` and other `OSError` failures are recorded as warnings.
- Empty files are scanned safely and produce no detections.
- The scanner separates scan failure from malware detection; detections do not crash or abort the run.

## Advanced Heuristics

Sentinel implements two advanced heuristic categories:

- `Heuristic_API`: for Windows PE files beginning with `MZ`, Sentinel uses `pefile` to parse the Import Address Table. Imports such as `CreateRemoteThread`, `VirtualAllocEx`, and `WriteProcessMemory` raise MEDIUM or HIGH risk depending on how many are present.
- `Heuristic_Entropy`: Sentinel computes Shannon entropy from byte frequencies. Files above 7.5 entropy and at least 1024 bytes are flagged because high randomness may indicate packing or encryption.

If `pefile` is unavailable, PE IAT analysis is skipped with a warning; signature
scanning and entropy analysis still run.

## Reporting And Benchmarking

JSON reports include `infected_path`, `threat_name`, `severity`, `match_type`,
`timestamp`, scan summary counts, warnings, and benchmark fields. The CLI
`--benchmark` option prints total scanned files, total scan time, files/sec,
average MB/s, and total bytes read. These metrics can be copied into the final
written report to justify the hybrid architecture.

Demo command:

```bash
python3 -m sentinel scan samples/demo --db data/signatures.db --bloom data/filter.bloom --report reports/scan.json --text-report reports/scan.txt --benchmark
```

Expected demo detections:

- EICAR test file as `Signature`.
- Mock pattern payload as `Signature`.
- High-entropy sample as `Heuristic_Entropy`.

## Limitations

Sentinel is an educational scanner. It does not unpack archives, emulate
execution, scan memory, or detect every unknown malware family. The Bloom filter
can produce false positives, which SQLite resolves during the second lookup
stage. PE heuristic quality depends on the availability and correctness of the
`pefile` parser.
