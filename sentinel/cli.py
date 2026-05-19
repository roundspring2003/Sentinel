from __future__ import annotations

import argparse
from pathlib import Path

from .heuristics import DEFAULT_HEURISTIC_RULES
from .scanner import scan_path, write_json_report, write_text_report
from .signatures import load_signature_database


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = PROJECT_ROOT / "data" / "signatures.json"
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "scan.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel signature-based virus scanner.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a file or directory")
    scan_parser.add_argument("target", help="file or directory to scan")
    scan_parser.add_argument("--db", default=str(DEFAULT_DB), help="path to signatures JSON database")
    scan_parser.add_argument("--report", default=str(DEFAULT_REPORT), help="path to write JSON report")
    scan_parser.add_argument("--text-report", help="optional path to write a plain-text report")
    scan_parser.add_argument(
        "--no-heuristics",
        action="store_true",
        help="disable heuristic suspicious-string analysis",
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
    database = load_signature_database(args.db)
    heuristic_rules = () if args.no_heuristics else DEFAULT_HEURISTIC_RULES
    result = scan_path(args.target, database, heuristic_rules=heuristic_rules)

    write_json_report(result, args.report)
    if args.text_report:
        write_text_report(result, args.text_report)

    print(f"Scanned files: {result.scanned_file_count}")
    print(f"Skipped files: {result.skipped_file_count}")
    print(f"Detections: {result.detection_count}")
    print(f"Warnings: {len(result.warnings)}")
    print(f"JSON report: {Path(args.report).resolve()}")

    if result.detections:
        print("Detected threats:")
        for detection in result.detections:
            matched_by = ", ".join(detection.matched_by)
            print(f"- [{detection.severity}] {detection.path}: {detection.threat_name} ({matched_by})")

    return 0
