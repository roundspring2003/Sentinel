from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import tracemalloc

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from build_db import build_database  # noqa: E402
from sentinel.bloom import BloomFilter  # noqa: E402
from sentinel.scanner import scan_path, write_json_report, write_text_report  # noqa: E402
from sentinel.signatures import load_signature_store  # noqa: E402


EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DEFAULT_COUNTS = (1_000, 10_000, 50_000, 100_000, 250_000)
LARGE_COUNTS = (500_000, 1_000_000)
FALSE_POSITIVE_RATE = 0.01


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Sentinel report charts and demo evidence.")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "reports"), help="directory for chart/report outputs")
    parser.add_argument("--demo-dir", default=str(PROJECT_ROOT / "samples" / "report_demo"), help="demo scenario directory")
    parser.add_argument(
        "--counts",
        nargs="+",
        type=int,
        help="explicit signature counts to measure; defaults to the safe empirical set",
    )
    parser.add_argument(
        "--large",
        action="store_true",
        help="also measure 500K and 1M signatures; this can consume significant RAM and time",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    demo_dir = Path(args.demo_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    counts = tuple(args.counts) if args.counts else DEFAULT_COUNTS + (LARGE_COUNTS if args.large else ())
    memory_rows = generate_memory_data(counts)
    write_csv(output_dir / "memory_architecture.csv", memory_rows)
    write_csv(output_dir / "memory_measurements.csv", memory_rows)
    write_memory_svg(output_dir / "memory_architecture.svg", memory_rows)

    build_database(
        source=PROJECT_ROOT / "data" / "signatures.json",
        sqlite_output=PROJECT_ROOT / "data" / "signatures.db",
        bloom_output=PROJECT_ROOT / "data" / "filter.bloom",
    )
    prepare_demo_scenario(demo_dir)
    demo_summary = run_demo_scan(demo_dir, output_dir)
    write_demo_video_script(output_dir / "demo_video_script.md", demo_dir)

    summary = {
        "memory_chart": str((output_dir / "memory_architecture.svg").resolve()),
        "memory_csv": str((output_dir / "memory_architecture.csv").resolve()),
        "measured_csv": str((output_dir / "memory_measurements.csv").resolve()),
        "measurement_method": "Both lines use tracemalloc retained-memory measurements on synthetic signatures.",
        "measured_signature_counts": list(counts),
        "demo_scan_json": str((output_dir / "report_demo_scan.json").resolve()),
        "demo_scan_text": str((output_dir / "report_demo_scan.txt").resolve()),
        "demo_video_script": str((output_dir / "demo_video_script.md").resolve()),
        "demo_summary": demo_summary,
    }
    (output_dir / "report_artifacts_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print("Generated report artifacts:")
    for key, value in summary.items():
        if key != "demo_summary":
            print(f"- {key}: {value}")
    print("Demo summary:")
    print(json.dumps(demo_summary, indent=2))
    return 0


def generate_memory_data(counts: tuple[int, ...]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for count in counts:
        traditional_current, traditional_peak = measure_traditional_hashmap_bytes(count)
        bloom_current, bloom_peak, bloom_bits, bloom_hash_count = measure_bloom_filter_bytes(count)
        rows.append(
            {
                "signature_count": str(count),
                "traditional_hashmap_mb": _mb(traditional_current),
                "sentinel_bloom_mb": _mb(bloom_current),
                "traditional_peak_mb": _mb(traditional_peak),
                "sentinel_bloom_peak_mb": _mb(bloom_peak),
                "bloom_bits": str(bloom_bits),
                "bloom_hash_count": str(bloom_hash_count),
                "false_positive_rate": str(FALSE_POSITIVE_RATE),
                "method": "empirical_tracemalloc_current_memory",
            }
        )
    return rows


def measure_traditional_hashmap_bytes(signature_count: int) -> tuple[int, int]:
    tracemalloc.start()
    records = []
    md5_map = {}
    sha256_map = {}

    for index in range(signature_count):
        seed = f"signature-{index}".encode("utf-8")
        md5 = hashlib.md5(seed).hexdigest()
        sha256 = hashlib.sha256(seed).hexdigest()
        record = {
            "id": f"SIG.{index:08d}",
            "name": f"Synthetic signature {index}",
            "severity": "HIGH" if index % 5 == 0 else "MEDIUM",
            "md5": md5,
            "sha256": sha256,
            "hex_pattern": None,
            "description": "Synthetic record used only for memory benchmarking.",
        }
        records.append(record)
        md5_map[md5] = record
        sha256_map[sha256] = record

    current, peak = tracemalloc.get_traced_memory()
    # Keep objects live until after memory is read.
    if len(records) + len(md5_map) + len(sha256_map) < 0:
        raise RuntimeError("unreachable")
    tracemalloc.stop()
    return current, peak


def measure_bloom_filter_bytes(signature_count: int) -> tuple[int, int, int, int]:
    tracemalloc.start()
    bloom = BloomFilter.create(
        expected_items=signature_count * 2,
        false_positive_rate=FALSE_POSITIVE_RATE,
    )
    for index in range(signature_count):
        seed = f"signature-{index}".encode("utf-8")
        bloom.add(hashlib.md5(seed).hexdigest())
        bloom.add(hashlib.sha256(seed).hexdigest())

    current, peak = tracemalloc.get_traced_memory()
    if bloom.size_bits < 0:
        raise RuntimeError("unreachable")
    size_bits = bloom.size_bits
    hash_count = bloom.hash_count
    tracemalloc.stop()
    return current, peak, size_bits, hash_count


def _mb(value: int) -> str:
    return f"{value / (1024 * 1024):.4f}"


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_memory_svg(path: Path, rows: list[dict[str, str]]) -> None:
    width, height = 980, 560
    left, right, top, bottom = 95, 45, 62, 88
    plot_w = width - left - right
    plot_h = height - top - bottom
    counts = [int(row["signature_count"]) for row in rows]
    red = [float(row["traditional_hashmap_mb"]) for row in rows]
    blue = [float(row["sentinel_bloom_mb"]) for row in rows]
    x_min, x_max = min(counts), max(counts)
    if x_min == x_max:
        x_min = 0
    y_max = max(max(red), max(blue), 0.01) * 1.08

    def x_scale(value: int) -> float:
        return left + ((value - x_min) / (x_max - x_min)) * plot_w

    def y_scale(value: float) -> float:
        return top + (1 - value / y_max) * plot_h

    def points(values: list[float]) -> str:
        return " ".join(f"{x_scale(count):.2f},{y_scale(value):.2f}" for count, value in zip(counts, values))

    def fmt_count(value: int) -> str:
        if value >= 1_000_000:
            return f"{value / 1_000_000:g}M"
        if value >= 1_000:
            return f"{value // 1_000}K"
        return str(value)

    grid_lines = []
    for step in range(6):
        value = y_max * step / 5
        y = y_scale(value)
        grid_lines.append(f'<line x1="{left}" y1="{y:.2f}" x2="{width-right}" y2="{y:.2f}" stroke="#e5e7eb"/>')
        grid_lines.append(f'<text x="{left-12}" y="{y+4:.2f}" text-anchor="end" class="tick">{value:.0f}</text>')

    x_ticks = []
    for count in counts:
        x = x_scale(count)
        x_ticks.append(f'<line x1="{x:.2f}" y1="{top}" x2="{x:.2f}" y2="{height-bottom}" stroke="#f1f5f9"/>')
        x_ticks.append(f'<text x="{x:.2f}" y="{height-bottom+28}" text-anchor="middle" class="tick">{fmt_count(count)}</text>')

    blue_last = (x_scale(counts[-1]), y_scale(blue[-1]))
    red_last = (x_scale(counts[-1]), y_scale(red[-1]))
    last_label = fmt_count(counts[-1])

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <style>
    .title {{ font: 700 24px Arial, sans-serif; fill: #111827; }}
    .subtitle {{ font: 14px Arial, sans-serif; fill: #4b5563; }}
    .axis {{ stroke: #111827; stroke-width: 1.4; }}
    .tick {{ font: 12px Arial, sans-serif; fill: #4b5563; }}
    .label {{ font: 13px Arial, sans-serif; fill: #111827; }}
    .legend {{ font: 14px Arial, sans-serif; fill: #111827; }}
  </style>
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{left}" y="32" class="title">Sentinel Memory Architecture Comparison</text>
  <text x="{left}" y="52" class="subtitle">Both lines are empirical tracemalloc retained-memory measurements on the same synthetic signature counts.</text>
  {''.join(grid_lines)}
  {''.join(x_ticks)}
  <line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" class="axis"/>
  <line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" class="axis"/>
  <polyline points="{points(red)}" fill="none" stroke="#dc2626" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  <polyline points="{points(blue)}" fill="none" stroke="#2563eb" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="{red_last[0]:.2f}" cy="{red_last[1]:.2f}" r="5" fill="#dc2626"/>
  <circle cx="{blue_last[0]:.2f}" cy="{blue_last[1]:.2f}" r="5" fill="#2563eb"/>
  <text x="{red_last[0]-12:.2f}" y="{red_last[1]-12:.2f}" text-anchor="end" class="label">Traditional: {red[-1]:.2f} MB at {last_label}</text>
  <text x="{blue_last[0]-12:.2f}" y="{blue_last[1]-10:.2f}" text-anchor="end" class="label">Sentinel Bloom: {blue[-1]:.2f} MB at {last_label}</text>
  <line x1="{left+26}" y1="{top+26}" x2="{left+76}" y2="{top+26}" stroke="#dc2626" stroke-width="4"/>
  <text x="{left+86}" y="{top+31}" class="legend">Traditional JSON → Python Hash Map</text>
  <line x1="{left+26}" y1="{top+52}" x2="{left+76}" y2="{top+52}" stroke="#2563eb" stroke-width="4"/>
  <text x="{left+86}" y="{top+57}" class="legend">Sentinel Bloom Filter in memory</text>
  <text x="{width/2}" y="{height-22}" text-anchor="middle" class="label">Signature count</text>
  <text x="22" y="{height/2}" text-anchor="middle" transform="rotate(-90 22 {height/2})" class="label">Measured retained memory usage (MB)</text>
</svg>
'''
    path.write_text(svg, encoding="utf-8")


def prepare_demo_scenario(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    restricted = root / "edge_cases" / "restricted_system_file.bin"
    if restricted.exists():
        restricted.chmod(0o600)

    deep = root / "level1" / "level2" / "level3" / "level4" / "level5"
    edge_cases = root / "edge_cases"
    suspicious = root / "suspicious"
    clean = root / "clean"
    for directory in (deep, edge_cases, suspicious, clean):
        directory.mkdir(parents=True, exist_ok=True)

    (deep / "eicar_hidden.txt").write_bytes(EICAR_BYTES)
    (edge_cases / "empty.bin").write_bytes(b"")
    restricted.write_bytes(b"simulated system file that should trigger PermissionError\n")
    restricted.chmod(0)
    (clean / "notes.txt").write_text("clean file for comparison\n", encoding="utf-8")
    (suspicious / "mock_payload.txt").write_text("MALWARE_SIMULATION_PAYLOAD\n", encoding="utf-8")
    (suspicious / "mock_iat.exe").write_bytes(
        b"MZ" + b"\x00" * 128 +
        b"\nSENTINEL_MOCK_IAT: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\n"
    )

    loop_link = root / "edge_cases" / "loop_link"
    if loop_link.exists() or loop_link.is_symlink():
        loop_link.unlink()
    try:
        os.symlink(root, loop_link, target_is_directory=True)
    except OSError:
        pass


def run_demo_scan(demo_dir: Path, output_dir: Path) -> dict[str, object]:
    store = load_signature_store(PROJECT_ROOT / "data" / "signatures.db", PROJECT_ROOT / "data" / "filter.bloom")
    started = time.perf_counter()
    try:
        result = scan_path(demo_dir, store, max_workers=4)
    finally:
        store.close()
    elapsed = time.perf_counter() - started

    write_json_report(result, output_dir / "report_demo_scan.json")
    write_text_report(result, output_dir / "report_demo_scan.txt")

    return {
        "scanned_file_count": result.scanned_file_count,
        "skipped_file_count": result.skipped_file_count,
        "warning_count": len(result.warnings),
        "detection_count": result.detection_count,
        "duration_seconds": round(result.duration_seconds, 6),
        "wall_time_seconds": round(elapsed, 6),
        "files_per_second": round(result.files_per_second, 4),
        "megabytes_per_second": round(result.megabytes_per_second, 4),
        "detections": [
            {
                "path": detection.path,
                "threat_name": detection.threat_name,
                "match_type": detection.match_type,
                "severity": detection.severity,
                "matched_by": detection.matched_by,
            }
            for detection in result.detections
        ],
        "warnings": [warning.to_dict() for warning in result.warnings],
    }


def write_demo_video_script(path: Path, demo_dir: Path) -> None:
    relative_demo = demo_dir.relative_to(PROJECT_ROOT)
    path.write_text(
        f"""# Sentinel Demo Video Script

1. Show the hybrid artifacts:

```bash
python3 build_db.py
ls -lh data/signatures.db data/filter.bloom
```

2. Generate and show the memory chart:

```bash
python3 scripts/generate_report_artifacts.py
```

Open `reports/memory_architecture.svg`. Explain that the red line is the traditional JSON/HashMap memory model, while the blue line is Sentinel's Bloom filter memory model.

3. Show the nested EICAR and mock IAT demo files:

```bash
find {relative_demo} -maxdepth 8 -type f -print -o -type l -print
```

Point out these files:

- `level1/level2/level3/level4/level5/eicar_hidden.txt`
- `edge_cases/empty.bin`
- `edge_cases/restricted_system_file.bin`
- `edge_cases/loop_link`
- `suspicious/mock_iat.exe`
- `suspicious/mock_payload.txt`

4. Run the scanner with benchmark mode:

```bash
python3 -m sentinel scan {relative_demo} --db data/signatures.db --bloom data/filter.bloom --report reports/report_demo_scan.json --text-report reports/report_demo_scan.txt --benchmark --workers 4 --executor process
```

5. Highlight the results:

- EICAR is detected through `Signature` with `md5`, `sha256`, and `hex_pattern`.
- Mock payload is detected through `Signature` with `hex_pattern`.
- Mock IAT sample is detected through `Heuristic_API`.
- Empty, restricted, and symlink edge cases do not crash the scanner.
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
