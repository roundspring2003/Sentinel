# Sentinel Report Validation Results

## Figure 1: Memory Architecture Value

Generated chart:

- `reports/memory_architecture.svg`
- Source data: `reports/memory_architecture.csv`
- Measurement data: `reports/memory_measurements.csv`

This experiment now uses an empirical method for both lines. For each synthetic
signature count, the script uses Python `tracemalloc` to measure retained memory
for two lookup architectures built from the same synthetic signature set:

- Red line: traditional JSON-style Python records plus `md5` and `sha256` hash maps.
- Blue line: Sentinel's actual `BloomFilter` object after inserting the same MD5/SHA-256 values.

No plotted point is produced by formula-only estimation or linear extrapolation.
The default experiment intentionally stops at 250,000 signatures to keep the
benchmark reproducible on ordinary lab machines. Larger runs can be generated
with `python3 scripts/generate_report_artifacts.py --large` if the machine has
enough RAM and time.

Key empirical data points from the latest run:

| Signature count | Traditional JSON/HashMap | Sentinel Bloom Filter |
| ---: | ---: | ---: |
| 1,000 | 0.5974 MB | 0.0027 MB |
| 10,000 | 5.8882 MB | 0.0233 MB |
| 50,000 | 31.2073 MB | 0.1147 MB |
| 100,000 | 62.3460 MB | 0.2293 MB |
| 250,000 | 152.4151 MB | 0.5717 MB |

Suggested report wording:

> To avoid relying on theory-only estimates, both lookup architectures were
> measured with Python `tracemalloc` on the same synthetic signature counts. The
> traditional JSON/HashMap approach keeps full Python records and two digest
> maps in memory, causing retained memory to grow quickly as signatures increase.
> Sentinel keeps only the compact Bloom Filter in memory and leaves full
> signature metadata in SQLite. At 250,000 synthetic signatures, the traditional
> structure retained about 152.42 MB, while Sentinel's Bloom Filter retained
> about 0.57 MB. This empirical result supports the project goal of reducing
> memory pressure while preserving fast signature pre-checks.

## Demo Validation

Generated demo scenario:

- `samples/report_demo/level1/level2/level3/level4/level5/eicar_hidden.txt`
- `samples/report_demo/suspicious/mock_payload.txt`
- `samples/report_demo/suspicious/mock_iat.exe`
- `samples/report_demo/edge_cases/empty.bin`
- `samples/report_demo/edge_cases/restricted_system_file.bin`
- `samples/report_demo/edge_cases/loop_link`

Generated reports:

- `reports/report_demo_scan.json`
- `reports/report_demo_scan.txt`
- `reports/demo_video_script.md`

Latest validation result:

- Scanned files: 5
- Skipped files: 1
- Warnings: 2
- Detections: 3
- Scan duration: about 0.002 seconds in this local run

Detected threats:

| File | Detection | Match type | Evidence |
| --- | --- | --- | --- |
| `eicar_hidden.txt` | EICAR test file | `Signature` | `md5`, `sha256`, `hex_pattern` |
| `mock_payload.txt` | Mock malware payload | `Signature` | `hex_pattern` |
| `mock_iat.exe` | Suspicious PE imports | `Heuristic_API` | `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` |

Edge cases:

| Case | Result |
| --- | --- |
| Empty file | Scanned safely, no crash |
| Restricted file | Warning logged, scan continued |
| Symlink loop | Warning logged, link skipped |

Suggested report wording:

> The EICAR test file was placed inside a five-level nested directory structure
> and mixed with empty files, a restricted file, a symlink loop, a mock signature
> payload, and a classroom-safe mock IAT sample. Sentinel completed the scan
> without crashing, detected EICAR through hash and pattern signatures, detected
> the mock payload through hex-pattern matching, and triggered a `Heuristic_API`
> warning for the mock IAT sample. Permission and symlink edge cases were logged
> as warnings while the scanner continued execution.


## Parallel Throughput Benchmark

Generated artifacts:

- `reports/parallel_scan_benchmark.csv`
- `reports/parallel_scan_benchmark.json`
- `reports/parallel_scan_benchmark.svg`
- `reports/parallel_scan_benchmark.md`

Benchmark setup:

- Mixed files: 10,000
- Regular payload size: 4,096 bytes
- Repeats: 3 per executor/worker setting
- Executors: `thread`, `process`
- Worker settings: 1, 2, 4, 8
- Categories: clean text, clean binary, EICAR, mock hex-pattern payload, mock IAT PE sample, empty files

Latest empirical result:

| Executor | Workers | Avg files/sec | Avg MB/s | Avg duration | Speedup vs baseline | Gain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| thread | 1 | 9059.42 | 34.65 | 1.1038s | 1.00x | 0.00% |
| thread | 2 | 7933.55 | 30.34 | 1.2605s | 0.88x | -12.43% |
| thread | 4 | 6834.55 | 26.14 | 1.4632s | 0.75x | -24.56% |
| thread | 8 | 6492.59 | 24.83 | 1.5403s | 0.72x | -28.33% |
| process | 1 | 9051.92 | 34.62 | 1.1047s | 1.00x | -0.08% |
| process | 2 | 15213.43 | 58.18 | 0.6574s | 1.68x | 67.93% |
| process | 4 | 26876.69 | 102.78 | 0.3723s | 2.97x | 196.67% |
| process | 8 | 33044.69 | 126.37 | 0.3026s | 3.65x | 264.75% |

Interpretation:

> Thread-based parallel scanning did not improve throughput because this scanner
> performs CPU-heavy Python work such as hashing, entropy counting, pattern
> checks, and heuristic analysis. These operations remain constrained by the
> Python GIL when executed in threads. After replacing threads with
> `ProcessPoolExecutor`, each worker ran in an independent Python interpreter
> with its own GIL and loaded its own Bloom/SQLite signature store. On the same
> 10,000-file mixed dataset, the best process configuration used 8 workers and
> reached about 33,045 files/sec, which is 3.65x faster than the 1-worker thread
> baseline and corresponds to a 264.75% throughput gain in this environment.

## Reproduction Commands

```bash
python3 build_db.py
python3 scripts/generate_report_artifacts.py
python3 scripts/benchmark_parallel_scan.py --file-count 10000 --payload-size 4096 --workers 1 2 4 8 --executors thread process --repeats 3
python3 -m sentinel scan samples/report_demo --db data/signatures.db --bloom data/filter.bloom --report reports/report_demo_scan.json --text-report reports/report_demo_scan.txt --benchmark --workers 4
```

Optional large benchmark:

```bash
python3 scripts/generate_report_artifacts.py --large
```
