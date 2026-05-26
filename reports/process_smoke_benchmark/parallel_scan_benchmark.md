# Parallel Scan Benchmark Results

Dataset:

- Files: 1000
- Payload size: 4096 bytes for regular generated files
- Categories: `{"clean_binary": 320, "clean_text": 640, "eicar": 1, "empty": 20, "mock_iat": 4, "mock_payload": 15}`

Headline:

- Baseline: `thread` with 1 worker, 8888.07 files/sec
- Best measured configuration: `process` with 2 worker(s), 14186.46 files/sec
- Speedup vs baseline: 1.60x
- Throughput gain vs baseline: 59.61%
- Best process mode: 2 worker(s), 14186.46 files/sec, 1.60x vs baseline, 59.61% gain

| Executor | Workers | Avg files/sec | Avg MB/s | Avg duration | Speedup | Gain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| process | 1 | 8729.19 | 33.38 | 0.1146s | 0.98x | -1.79% |
| process | 2 | 14186.46 | 54.25 | 0.0705s | 1.60x | 59.61% |
| thread | 1 | 8888.07 | 33.99 | 0.1125s | 1.00x | 0.00% |
| thread | 2 | 7946.84 | 30.39 | 0.1258s | 0.89x | -10.59% |


Suggested report wording:

> Sentinel was evaluated on a mixed dataset of 1000 files containing clean text, clean binary files, EICAR samples, mock hex-pattern payloads, mock IAT PE samples, and empty files. Compared with the single-worker thread baseline, the best configuration used `process` with 2 workers and reached 14186.46 files/sec, corresponding to a 1.60x speedup and a 59.61% throughput gain in this environment.
