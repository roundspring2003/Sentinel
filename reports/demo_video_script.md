# Sentinel Demo Video Script

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
find samples/report_demo -maxdepth 8 -type f -print -o -type l -print
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
python3 -m sentinel scan samples/report_demo --db data/signatures.db --bloom data/filter.bloom --report reports/report_demo_scan.json --text-report reports/report_demo_scan.txt --benchmark --workers 4 --executor process
```

5. Highlight the results:

- EICAR is detected through `Signature` with `md5`, `sha256`, and `hex_pattern`.
- Mock payload is detected through `Signature` with `hex_pattern`.
- Mock IAT sample is detected through `Heuristic_API`.
- Empty, restricted, and symlink edge cases do not crash the scanner.
