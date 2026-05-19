# Sentinel Virus Scanner

Sentinel is a classroom-safe, signature-based virus scanner written in Python.
It scans files without executing them, compares file hashes and byte patterns
against a JSON signature database, applies a small heuristic rule set, and
writes a security report.

## Project Structure

- `sentinel/`: Python scanner package and CLI.
- `data/signatures.json`: malware signature database.
- `samples/demo/`: clean, EICAR, and mock suspicious sample files.
- `reports/`: generated scan reports.
- `tests/`: unit tests for the required project scenarios.
- `PROJECT_REPORT.md`: written report draft for submission.

## Quick Start

Run from the `Project1` directory:

```bash
python3 -m sentinel scan samples/demo --db data/signatures.json --report reports/scan.json --text-report reports/scan.txt
```

Expected behavior:

- The clean sample is ignored.
- The EICAR test file is detected as a known signature.
- The mock pattern file is detected by hex-pattern matching.
- The mock injection file is detected by heuristic analysis.

## CLI

```bash
python3 -m sentinel scan <target> --db data/signatures.json --report reports/scan.json
```

Useful options:

- `--text-report reports/scan.txt`: also write a plain-text report.
- `--no-heuristics`: disable heuristic suspicious-string rules.

Detection reports include infected paths, threat names, severity levels,
match types, timestamps, scanned file counts, skipped file counts, and warnings.

## Tests

Run from the `Project1` directory:

```bash
python3 -m unittest discover tests
```

The tests cover clean folders, nested EICAR detection, hex-pattern detection,
heuristic API detection, empty files, and JSON report generation.

## Safety

The demo uses the EICAR antivirus test string and harmless mock text markers.
Do not add real malware samples to this project.
