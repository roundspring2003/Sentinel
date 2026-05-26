from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import statistics
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from build_db import build_database  # noqa: E402
from sentinel.scanner import scan_path  # noqa: E402
from sentinel.signatures import load_signature_store  # noqa: E402


EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DEFAULT_WORKERS = (1, 2, 4, 8)
DEFAULT_EXECUTORS = ("thread", "process")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Sentinel parallel scanning throughput.")
    parser.add_argument("--dataset", default=str(PROJECT_ROOT / "samples" / "throughput_benchmark"), help="benchmark dataset directory")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "reports"), help="output report directory")
    parser.add_argument("--file-count", type=int, default=10_000, help="number of mixed files to generate")
    parser.add_argument("--payload-size", type=int, default=4096, help="payload bytes per regular generated file")
    parser.add_argument("--workers", nargs="+", type=int, default=list(DEFAULT_WORKERS), help="worker counts to benchmark")
    parser.add_argument("--executors", nargs="+", choices=DEFAULT_EXECUTORS, default=list(DEFAULT_EXECUTORS), help="executor backends to benchmark")
    parser.add_argument("--repeats", type=int, default=3, help="scan repetitions per executor/worker count")
    parser.add_argument("--reuse", action="store_true", help="reuse existing dataset instead of regenerating it")
    parser.add_argument("--no-heuristics", action="store_true", help="disable heuristic analysis during benchmark")
    parser.add_argument("--no-patterns", action="store_true", help="disable hex-pattern checks during benchmark")
    args = parser.parse_args(argv)

    dataset = Path(args.dataset)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.reuse or not dataset.exists():
        manifest = prepare_dataset(dataset, args.file_count, args.payload_size)
    else:
        manifest = load_manifest(dataset)

    build_database(
        source=PROJECT_ROOT / "data" / "signatures.json",
        sqlite_output=PROJECT_ROOT / "data" / "signatures.db",
        bloom_output=PROJECT_ROOT / "data" / "filter.bloom",
    )

    rows = run_benchmark(
        dataset=dataset,
        workers=tuple(args.workers),
        executors=tuple(args.executors),
        repeats=args.repeats,
        enable_heuristics=not args.no_heuristics,
        enable_patterns=not args.no_patterns,
    )
    summary = summarize(rows, manifest)

    write_csv(output_dir / "parallel_scan_benchmark.csv", rows)
    (output_dir / "parallel_scan_benchmark.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    write_svg(output_dir / "parallel_scan_benchmark.svg", summary["worker_summaries"])
    write_markdown(output_dir / "parallel_scan_benchmark.md", summary)

    print("Parallel scan benchmark complete:")
    print(json.dumps(summary["headline"], indent=2))
    print(f"CSV: {(output_dir / 'parallel_scan_benchmark.csv').resolve()}")
    print(f"JSON: {(output_dir / 'parallel_scan_benchmark.json').resolve()}")
    print(f"SVG: {(output_dir / 'parallel_scan_benchmark.svg').resolve()}")
    print(f"Markdown: {(output_dir / 'parallel_scan_benchmark.md').resolve()}")
    return 0


def prepare_dataset(root: Path, file_count: int, payload_size: int) -> dict[str, object]:
    if file_count < 100:
        raise ValueError("file-count must be at least 100 for a mixed benchmark")
    if payload_size < 128:
        raise ValueError("payload-size must be at least 128 bytes")

    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    data_root = root / "files"
    data_root.mkdir()

    categories = {
        "clean_text": 0,
        "clean_binary": 0,
        "mock_payload": 0,
        "mock_iat": 0,
        "eicar": 0,
        "empty": 0,
    }
    total_bytes = 0

    for index in range(file_count):
        shard = data_root / f"bucket_{index % 100:03d}"
        shard.mkdir(exist_ok=True)
        category = choose_category(index)
        categories[category] += 1
        path = shard / f"sample_{index:06d}_{category}{extension_for(category)}"
        data = payload_for(index, category, payload_size)
        path.write_bytes(data)
        total_bytes += len(data)

    manifest = {
        "file_count": file_count,
        "payload_size": payload_size,
        "total_payload_bytes": total_bytes,
        "categories": categories,
        "scan_subdir": "files",
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def load_manifest(root: Path) -> dict[str, object]:
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing manifest: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def choose_category(index: int) -> str:
    if index % 1000 == 0:
        return "eicar"
    if index % 200 == 0:
        return "mock_iat"
    if index % 50 == 0:
        return "mock_payload"
    if index % 25 == 0:
        return "empty"
    if index % 3 == 0:
        return "clean_binary"
    return "clean_text"


def extension_for(category: str) -> str:
    if category == "mock_iat":
        return ".exe"
    if category in {"clean_binary", "empty"}:
        return ".bin"
    return ".txt"


def payload_for(index: int, category: str, payload_size: int) -> bytes:
    if category == "empty":
        return b""
    if category == "eicar":
        return EICAR_BYTES
    if category == "mock_payload":
        return repeat_to_size(
            f"clean-prefix-{index}\nMALWARE_SIMULATION_PAYLOAD\n".encode("utf-8"),
            payload_size,
        )
    if category == "mock_iat":
        return repeat_to_size(
            b"MZ" + b"\x00" * 128 + b"\nSENTINEL_MOCK_IAT: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\n",
            payload_size,
        )
    if category == "clean_binary":
        return deterministic_binary(index, payload_size)
    return repeat_to_size(
        f"clean text sample {index}\nThis file should not match signatures.\n".encode("utf-8"),
        payload_size,
    )


def repeat_to_size(seed: bytes, size: int) -> bytes:
    repeated = seed * ((size // len(seed)) + 1)
    return repeated[:size]


def deterministic_binary(index: int, size: int) -> bytes:
    # Low-entropy deterministic pattern to avoid intentionally triggering entropy heuristics.
    return bytes(((index + offset) % 64) for offset in range(size))


def run_benchmark(
    dataset: Path,
    workers: tuple[int, ...],
    executors: tuple[str, ...],
    repeats: int,
    enable_heuristics: bool,
    enable_patterns: bool,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    scan_target = dataset / "files" if (dataset / "files").exists() else dataset
    for executor_kind in executors:
        for worker_count in workers:
            for repeat in range(1, repeats + 1):
                store = load_signature_store(PROJECT_ROOT / "data" / "signatures.db", PROJECT_ROOT / "data" / "filter.bloom")
                started = time.perf_counter()
                try:
                    result = scan_path(
                        scan_target,
                        store,
                        max_workers=worker_count,
                        executor=executor_kind,
                        enable_heuristics=enable_heuristics,
                        enable_patterns=enable_patterns,
                    )
                finally:
                    store.close()
                wall_time = time.perf_counter() - started
                rows.append(
                    {
                        "executor": executor_kind,
                        "workers": str(worker_count),
                        "repeat": str(repeat),
                        "duration_seconds": f"{result.duration_seconds:.6f}",
                        "wall_time_seconds": f"{wall_time:.6f}",
                        "scanned_file_count": str(result.scanned_file_count),
                        "skipped_file_count": str(result.skipped_file_count),
                        "detection_count": str(result.detection_count),
                        "warning_count": str(len(result.warnings)),
                        "total_bytes_read": str(result.total_bytes_read),
                        "files_per_second": f"{result.files_per_second:.4f}",
                        "megabytes_per_second": f"{result.megabytes_per_second:.4f}",
                    }
                )
    return rows


def summarize(rows: list[dict[str, str]], manifest: dict[str, object]) -> dict[str, object]:
    grouped: dict[tuple[str, int], list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault((row["executor"], int(row["workers"])), []).append(row)

    worker_summaries = []
    for executor_kind, worker_count in sorted(grouped, key=lambda item: (item[0][0], item[0][1])):
        values = grouped[(executor_kind, worker_count)]
        durations = [float(row["duration_seconds"]) for row in values]
        fps_values = [float(row["files_per_second"]) for row in values]
        mbps_values = [float(row["megabytes_per_second"]) for row in values]
        worker_summaries.append(
            {
                "executor": executor_kind,
                "workers": worker_count,
                "runs": len(values),
                "avg_duration_seconds": round(statistics.mean(durations), 6),
                "median_duration_seconds": round(statistics.median(durations), 6),
                "avg_files_per_second": round(statistics.mean(fps_values), 4),
                "median_files_per_second": round(statistics.median(fps_values), 4),
                "avg_megabytes_per_second": round(statistics.mean(mbps_values), 4),
                "median_megabytes_per_second": round(statistics.median(mbps_values), 4),
                "scanned_file_count": int(values[0]["scanned_file_count"]),
                "detection_count": int(values[0]["detection_count"]),
                "warning_count": int(values[0]["warning_count"]),
            }
        )

    baseline = _select_baseline(worker_summaries)
    baseline_fps = baseline["avg_files_per_second"]
    for item in worker_summaries:
        item["speedup_vs_baseline"] = round(item["avg_files_per_second"] / baseline_fps, 4) if baseline_fps else 0.0
        item["throughput_gain_percent"] = round((item["speedup_vs_baseline"] - 1) * 100, 2)

    best = max(worker_summaries, key=lambda item: item["avg_files_per_second"])
    best_process = max(
        (item for item in worker_summaries if item["executor"] == "process"),
        key=lambda item: item["avg_files_per_second"],
        default=None,
    )
    headline = {
        "baseline_executor": baseline["executor"],
        "baseline_workers": baseline["workers"],
        "baseline_files_per_second": baseline["avg_files_per_second"],
        "best_executor": best["executor"],
        "best_workers": best["workers"],
        "best_files_per_second": best["avg_files_per_second"],
        "best_speedup_vs_baseline": best["speedup_vs_baseline"],
        "best_throughput_gain_percent": best["throughput_gain_percent"],
    }
    if best_process is not None:
        headline.update(
            {
                "best_process_workers": best_process["workers"],
                "best_process_files_per_second": best_process["avg_files_per_second"],
                "best_process_speedup_vs_baseline": best_process["speedup_vs_baseline"],
                "best_process_throughput_gain_percent": best_process["throughput_gain_percent"],
            }
        )

    return {
        "benchmark_name": "parallel_scan_throughput",
        "manifest": manifest,
        "headline": headline,
        "worker_summaries": worker_summaries,
        "raw_runs": rows,
    }


def _select_baseline(worker_summaries: list[dict[str, object]]) -> dict[str, object]:
    for item in worker_summaries:
        if item["executor"] == "thread" and item["workers"] == 1:
            return item
    return min(worker_summaries, key=lambda item: (item["workers"], item["executor"]))


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_svg(path: Path, summaries: list[dict[str, object]]) -> None:
    width, height = 1080, 540
    left, right, top, bottom = 86, 42, 70, 96
    plot_w = width - left - right
    plot_h = height - top - bottom
    fps = [float(item["avg_files_per_second"]) for item in summaries]
    speedups = [float(item["speedup_vs_baseline"]) for item in summaries]
    y_max = max(fps) * 1.15 if fps else 1
    bar_gap = 16
    bar_w = max(24, (plot_w - bar_gap * (len(summaries) - 1)) / len(summaries))

    bars = []
    text = []
    for idx, (value, speedup, item) in enumerate(zip(fps, speedups, summaries)):
        x = left + idx * (bar_w + bar_gap)
        bar_h = (value / y_max) * plot_h
        y = top + plot_h - bar_h
        color = "#16a34a" if item["executor"] == "process" else "#2563eb"
        if speedup < 1:
            color = "#dc2626" if item["executor"] == "process" else "#f97316"
        bars.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_w:.2f}" height="{bar_h:.2f}" fill="{color}" rx="4"/>')
        text.append(f'<text x="{x + bar_w / 2:.2f}" y="{height - bottom + 24}" text-anchor="middle" class="tick">{item["executor"]}</text>')
        text.append(f'<text x="{x + bar_w / 2:.2f}" y="{height - bottom + 42}" text-anchor="middle" class="tick">{item["workers"]}w</text>')
        text.append(f'<text x="{x + bar_w / 2:.2f}" y="{y - 8:.2f}" text-anchor="middle" class="label">{value:.0f}</text>')
        text.append(f'<text x="{x + bar_w / 2:.2f}" y="{y + 18:.2f}" text-anchor="middle" class="bartext">{speedup:.2f}x</text>')

    grid_lines = []
    for step in range(6):
        value = y_max * step / 5
        y = top + plot_h - (value / y_max) * plot_h
        grid_lines.append(f'<line x1="{left}" y1="{y:.2f}" x2="{width-right}" y2="{y:.2f}" stroke="#e5e7eb"/>')
        grid_lines.append(f'<text x="{left-10}" y="{y+4:.2f}" text-anchor="end" class="tick">{value:.0f}</text>')

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <style>
    .title {{ font: 700 24px Arial, sans-serif; fill: #111827; }}
    .subtitle {{ font: 14px Arial, sans-serif; fill: #4b5563; }}
    .axis {{ stroke: #111827; stroke-width: 1.4; }}
    .tick {{ font: 12px Arial, sans-serif; fill: #4b5563; }}
    .label {{ font: 13px Arial, sans-serif; fill: #111827; }}
    .bartext {{ font: 12px Arial, sans-serif; fill: #ffffff; font-weight: 700; }}
  </style>
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{left}" y="34" class="title">Sentinel Parallel Scan Throughput</text>
  <text x="{left}" y="55" class="subtitle">Average files/sec across repeated scans; process mode bypasses the GIL for CPU-heavy hash/entropy work.</text>
  {''.join(grid_lines)}
  <line x1="{left}" y1="{top}" x2="{left}" y2="{height-bottom}" class="axis"/>
  <line x1="{left}" y1="{height-bottom}" x2="{width-right}" y2="{height-bottom}" class="axis"/>
  {''.join(bars)}
  {''.join(text)}
  <text x="{width/2}" y="{height-24}" text-anchor="middle" class="label">Executor and workers</text>
  <text x="22" y="{height/2}" text-anchor="middle" transform="rotate(-90 22 {height/2})" class="label">Average throughput (files/sec)</text>
</svg>
'''
    path.write_text(svg, encoding="utf-8")


def write_markdown(path: Path, summary: dict[str, object]) -> None:
    headline = summary["headline"]
    manifest = summary["manifest"]
    rows = summary["worker_summaries"]
    table = "| Executor | Workers | Avg files/sec | Avg MB/s | Avg duration | Speedup | Gain |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n"
    for row in rows:
        table += (
            f"| {row['executor']} | {row['workers']} | {row['avg_files_per_second']:.2f} | {row['avg_megabytes_per_second']:.2f} | "
            f"{row['avg_duration_seconds']:.4f}s | {row['speedup_vs_baseline']:.2f}x | {row['throughput_gain_percent']:.2f}% |\n"
        )

    if headline["best_executor"] == headline["baseline_executor"] and headline["best_workers"] == headline["baseline_workers"]:
        wording = (
            f"> Sentinel was evaluated on a mixed dataset of {manifest['file_count']} files containing clean text, clean binary files, "
            "EICAR samples, mock hex-pattern payloads, mock IAT PE samples, and empty files. In this workload, the single-worker "
            f"baseline was the fastest configuration at {headline['baseline_files_per_second']:.2f} files/sec. Neither threading nor multiprocessing "
            "improved throughput, which suggests that this benchmark is dominated by per-file overhead and small-file scheduling costs rather than CPU parallelism."
        )
    else:
        wording = (
            f"> Sentinel was evaluated on a mixed dataset of {manifest['file_count']} files containing clean text, clean binary files, "
            "EICAR samples, mock hex-pattern payloads, mock IAT PE samples, and empty files. Compared with the single-worker thread baseline, "
            f"the best configuration used `{headline['best_executor']}` with {headline['best_workers']} workers and reached {headline['best_files_per_second']:.2f} files/sec, "
            f"corresponding to a {headline['best_speedup_vs_baseline']:.2f}x speedup and a {headline['best_throughput_gain_percent']:.2f}% throughput gain in this environment."
        )

    process_line = ""
    if "best_process_workers" in headline:
        process_line = (
            f"- Best process mode: {headline['best_process_workers']} worker(s), "
            f"{headline['best_process_files_per_second']:.2f} files/sec, "
            f"{headline['best_process_speedup_vs_baseline']:.2f}x vs baseline, "
            f"{headline['best_process_throughput_gain_percent']:.2f}% gain\n"
        )

    path.write_text(
        f"""# Parallel Scan Benchmark Results

Dataset:

- Files: {manifest['file_count']}
- Payload size: {manifest['payload_size']} bytes for regular generated files
- Categories: `{json.dumps(manifest['categories'], sort_keys=True)}`

Headline:

- Baseline: `{headline['baseline_executor']}` with {headline['baseline_workers']} worker, {headline['baseline_files_per_second']:.2f} files/sec
- Best measured configuration: `{headline['best_executor']}` with {headline['best_workers']} worker(s), {headline['best_files_per_second']:.2f} files/sec
- Speedup vs baseline: {headline['best_speedup_vs_baseline']:.2f}x
- Throughput gain vs baseline: {headline['best_throughput_gain_percent']:.2f}%
{process_line}
{table}

Suggested report wording:

{wording}
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
