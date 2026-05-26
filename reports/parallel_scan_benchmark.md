# Parallel Scan Benchmark Results

Dataset:

- Files: 10000
- Payload size: 4096 bytes for regular generated files
- Categories: `{"clean_binary": 3200, "clean_text": 6400, "eicar": 10, "empty": 200, "mock_iat": 40, "mock_payload": 150}`

Headline:

- Baseline: `thread` with 1 worker, 9059.42 files/sec
- Best measured configuration: `process` with 8 worker(s), 33044.69 files/sec
- Speedup vs baseline: 3.65x
- Throughput gain vs baseline: 264.75%
- Best process mode: 8 worker(s), 33044.69 files/sec, 3.65x vs baseline, 264.75% gain

| Executor | Workers | Avg files/sec | Avg MB/s | Avg duration | Speedup | Gain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| process | 1 | 9051.92 | 34.62 | 1.1047s | 1.00x | -0.08% |
| process | 2 | 15213.43 | 58.18 | 0.6574s | 1.68x | 67.93% |
| process | 4 | 26876.69 | 102.78 | 0.3723s | 2.97x | 196.67% |
| process | 8 | 33044.69 | 126.37 | 0.3026s | 3.65x | 264.75% |
| thread | 1 | 9059.42 | 34.65 | 1.1038s | 1.00x | 0.00% |
| thread | 2 | 7933.55 | 30.34 | 1.2605s | 0.88x | -12.43% |
| thread | 4 | 6834.55 | 26.14 | 1.4632s | 0.75x | -24.56% |
| thread | 8 | 6492.59 | 24.83 | 1.5403s | 0.72x | -28.33% |


Suggested report wording:

> Sentinel was evaluated on a mixed dataset of 10000 files containing clean text, clean binary files, EICAR samples, mock hex-pattern payloads, mock IAT PE samples, and empty files. Compared with the single-worker thread baseline, the best configuration used `process` with 8 workers and reached 33044.69 files/sec, corresponding to a 3.65x speedup and a 264.75% throughput gain in this environment.
