from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .scanner import scan_path, write_json_report, write_text_report
from .signatures import load_signature_store


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = PROJECT_ROOT / "data" / "signatures.db"
DEFAULT_BLOOM = PROJECT_ROOT / "data" / "filter.bloom"
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "scan.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel hybrid Bloom-filter and SQLite virus scanner.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("target", help="file or directory to scan")
    scan_parser.add_argument("--db", default=str(DEFAULT_DB), help="path to SQLite signatures database")
    scan_parser.add_argument("--bloom", default=str(DEFAULT_BLOOM), help="path to serialized Bloom filter")
    scan_parser.add_argument("--report", default=str(DEFAULT_REPORT), help="path to write JSON report")
    scan_parser.add_argument("--text-report", help="optional path to write a plain-text report")
    scan_parser.add_argument("--workers", type=int, default=None, help="number of scan worker threads")
    scan_parser.add_argument("--benchmark", action="store_true", help="print scan performance metrics")
    scan_parser.add_argument(
        "--no-heuristics",
        action="store_true",
        help="disable PE IAT and entropy heuristic analysis",
    )
    scan_parser.add_argument(
        "--no-patterns",
        action="store_true",
        help="disable hex-pattern signature streaming checks",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.error(f"unknown command: {args.command}")
    return 2


def _run_scan(args: argparse.Namespace) -> int:
    db_path = Path(args.db)
    bloom_path = Path(args.bloom)
    missing = [str(path) for path in (db_path, bloom_path) if not path.exists()]
    if missing:
        print(
            "Missing scanner database artifact(s): " + ", ".join(missing),
            file=sys.stderr,
        )
        print("Run `python3 build_db.py` from Project1 first.", file=sys.stderr)
        return 2

    store = load_signature_store(db_path, bloom_path)
    try:
        result = scan_path(
            args.target,
            store,
            enable_heuristics=not args.no_heuristics,
            enable_patterns=not args.no_patterns,
            max_workers=args.workers,
        )
    finally:
        store.close()

    write_json_report(result, args.report)
    if args.text_report:
        write_text_report(result, args.text_report)

    print(f"Scanned files: {result.scanned_file_count}")
    print(f"Skipped files: {result.skipped_file_count}")
    print(f"Detections: {result.detection_count}")
    print(f"Warnings: {len(result.warnings)}")
    print(f"JSON report: {Path(args.report).resolve()}")

    if args.benchmark:
        print("Benchmark:")
        print(f"- Total scan time: {result.duration_seconds:.4f}s")
        print(f"- Files/sec: {result.files_per_second:.2f}")
        print(f"- Average disk throughput: {result.megabytes_per_second:.2f} MB/s")
        print(f"- Total bytes read: {result.total_bytes_read}")

    if result.detections:
        print("Detected threats:")
        for detection in result.detections:
            matched_by = ", ".join(detection.matched_by)
            print(f"- [{detection.severity}] {detection.path}: {detection.threat_name} ({detection.match_type}: {matched_by})")

    return 0
