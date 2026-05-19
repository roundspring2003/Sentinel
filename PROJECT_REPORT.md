# Sentinel Virus Scanner Project Report

## Overview

Sentinel is a functional signature-based virus scanner. It recursively scans a
target file or directory, computes MD5 and SHA-256 hashes, compares file bytes
against known hex patterns, applies simple heuristic rules, and writes a JSON
or text report. It never executes scanned files.

## Signature Database Design

The signature database is stored in `data/signatures.json`. Each record uses
the same fields: `id`, `name`, `severity`, `md5`, `sha256`, `hex_pattern`, and
`description`.

JSON was selected because it is human-readable, easy to edit for a small
classroom project, and directly supported by Python's standard library. In
memory, Sentinel converts the JSON list into hash maps:

- `md5_map`: maps an MD5 digest to one or more signatures.
- `sha256_map`: maps a SHA-256 digest to one or more signatures.
- `patterns`: stores signatures that include byte patterns.

The hash maps make exact hash lookup average O(1). Pattern matching scans file
content with byte search, which is simple and suitable for this project size.
For a larger production scanner, the pattern stage could be replaced with a
multi-pattern algorithm such as Aho-Corasick or with a Bloom filter pre-check.

## Scanning Engine

The scanner walks the target directory recursively using deterministic sorted
order. For each file, it:

1. Reads the file in chunks to compute MD5 and SHA-256.
2. Reads file bytes for hex-pattern and heuristic analysis.
3. Matches hashes against the in-memory hash maps.
4. Searches for known byte patterns.
5. Applies heuristic rules for suspicious strings such as `VirtualAllocEx`,
   `WriteProcessMemory`, and `CreateRemoteThread`.

Unreadable files are skipped with a warning instead of crashing the scanner.
Empty files are scanned normally and should produce no detections.

## Reporting

The JSON report includes the scan target, signature database path, generation
timestamp, scanned file count, skipped file count, detection count, infected
paths, detailed detections, and warnings. A plain-text report can also be
generated for easier reading during the demo.

## Demonstration Plan

The `samples/demo` folder contains:

- A clean text file.
- A nested EICAR test file.
- A mock file containing `MALWARE_SIMULATION_PAYLOAD`.
- A mock suspicious file containing process injection API names.

Run:

```bash
python3 -m sentinel scan samples/demo --db data/signatures.json --report reports/scan.json --text-report reports/scan.txt
```

The expected result is three detections: one EICAR signature, one mock pattern
signature, and one heuristic process-injection warning.

## Limitations

Sentinel is an educational scanner. It does not unpack archives, emulate
program behavior, scan memory, or detect unknown malware beyond simple
heuristic string rules. It is designed to demonstrate safe signature matching
and reporting concepts for the network security project.
