# Parallel Scan Benchmark Results

Dataset:

- Files: 1000
- Payload size: 2048 bytes for regular generated files
- Categories: `{"clean_binary": 320, "clean_text": 640, "eicar": 1, "empty": 20, "mock_iat": 4, "mock_payload": 15}`

Headline:

- Baseline: 1 worker, 10466.78 files/sec
- Best: 1 workers, 10466.78 files/sec
- Speedup: 1.00x
- Throughput gain: 0.00%

| Workers | Avg files/sec | Avg MB/s | Avg duration | Speedup | Gain |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 10466.78 | 20.00 | 0.0956s | 1.00x | 0.00% |
| 2 | 8839.05 | 16.89 | 0.1132s | 0.84x | -15.55% |


Suggested report wording:

> Sentinel was evaluated on a mixed dataset of 1000 files containing clean text, clean binary files, EICAR samples, mock hex-pattern payloads, mock IAT PE samples, and empty files. Compared with the single-worker baseline, the best parallel configuration used 1 workers and reached 10466.78 files/sec, corresponding to a 1.00x speedup and a 0.00% throughput gain in this environment.
