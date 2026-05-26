from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from build_db import build_database  # noqa: E402
from sentinel.scanner import scan_path, write_json_report  # noqa: E402
from sentinel.signatures import load_signature_store  # noqa: E402
import sentinel.heuristics as heuristics  # noqa: E402


EICAR_TEST_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db_tmp = TemporaryDirectory()
        tmp_path = Path(cls.db_tmp.name)
        cls.sqlite_path = tmp_path / "signatures.db"
        cls.bloom_path = tmp_path / "filter.bloom"
        build_database(
            source=PROJECT_ROOT / "data" / "signatures.json",
            sqlite_output=cls.sqlite_path,
            bloom_output=cls.bloom_path,
        )
        cls.store = load_signature_store(cls.sqlite_path, cls.bloom_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.store.close()
        cls.db_tmp.cleanup()

    def test_build_database_outputs_sqlite_and_bloom(self) -> None:
        with TemporaryDirectory() as tmp:
            sqlite_path = Path(tmp) / "signatures.db"
            bloom_path = Path(tmp) / "filter.bloom"

            signature_count, hash_count = build_database(
                source=PROJECT_ROOT / "data" / "signatures.json",
                sqlite_output=sqlite_path,
                bloom_output=bloom_path,
            )

            self.assertEqual(signature_count, 3)
            self.assertEqual(hash_count, 2)
            self.assertTrue(sqlite_path.exists())
            self.assertTrue(bloom_path.exists())

    def test_clean_folder_has_no_detections(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "clean.txt").write_text("ordinary class notes\n", encoding="utf-8")

            result = scan_path(root, self.store)

        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.detection_count, 0)
        self.assertEqual(result.skipped_file_count, 0)

    def test_eicar_in_nested_folder_is_detected_through_bloom_and_sqlite(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "a" / "b" / "c"
            nested.mkdir(parents=True)
            (nested / "eicar.txt").write_text(EICAR_TEST_STRING, encoding="utf-8")

            result = scan_path(root, self.store)

        eicar_detections = [d for d in result.detections if d.threat_id == "EICAR.TEST.FILE"]
        self.assertEqual(len(eicar_detections), 1)
        self.assertIn("md5", eicar_detections[0].matched_by)
        self.assertIn("sha256", eicar_detections[0].matched_by)
        self.assertEqual(eicar_detections[0].match_type, "Signature")

    def test_hex_pattern_mock_is_detected_without_loading_json(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mock.txt").write_text("prefix MALWARE_SIMULATION_PAYLOAD suffix", encoding="utf-8")

            result = scan_path(root, self.store)

        detections = [d for d in result.detections if d.threat_id == "MOCK.PATTERN.PAYLOAD"]
        self.assertEqual(len(detections), 1)
        self.assertIn("hex_pattern", detections[0].matched_by)

    def test_entropy_heuristic_detects_high_randomness(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packed.bin").write_bytes(bytes(range(256)) * 8)

            result = scan_path(root, self.store)

        detections = [d for d in result.detections if d.threat_id == "HEUR.ENTROPY.HIGH"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].match_type, "Heuristic_Entropy")
        self.assertGreaterEqual(detections[0].details["entropy"], 7.5)

    def test_pe_iat_heuristic_detects_suspicious_imports(self) -> None:
        class FakeImport:
            def __init__(self, name: str) -> None:
                self.name = name.encode("utf-8")

        class FakeEntry:
            imports = [
                FakeImport("VirtualAllocEx"),
                FakeImport("WriteProcessMemory"),
                FakeImport("CreateRemoteThread"),
            ]

        class FakePE:
            DIRECTORY_ENTRY_IMPORT = [FakeEntry()]

            def __init__(self, path: str, fast_load: bool = True) -> None:
                self.path = path
                self.fast_load = fast_load

            def parse_data_directories(self, directories: list[int]) -> None:
                self.directories = directories

            def close(self) -> None:
                pass

        class FakePefile:
            DIRECTORY_ENTRY = {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1}
            PE = FakePE

        old_pefile = heuristics.pefile
        heuristics.pefile = FakePefile
        try:
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "sample.exe").write_bytes(b"MZ" + (b"\x00" * 2048))

                result = scan_path(root, self.store)
        finally:
            heuristics.pefile = old_pefile

        detections = [d for d in result.detections if d.threat_id == "HEUR.PE.IAT.SUSPICIOUS_API"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].match_type, "Heuristic_API")
        self.assertEqual(detections[0].severity, "HIGH")


    def test_mock_iat_demo_marker_detects_suspicious_imports_without_pefile(self) -> None:
        old_pefile = heuristics.pefile
        heuristics.pefile = None
        try:
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "mock_iat.exe").write_bytes(
                    b"MZ"
                    + b"\x00" * 128
                    + b"\nSENTINEL_MOCK_IAT: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\n"
                )

                result = scan_path(root, self.store)
        finally:
            heuristics.pefile = old_pefile

        detections = [d for d in result.detections if d.threat_id == "HEUR.PE.IAT.SUSPICIOUS_API"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].match_type, "Heuristic_API")
        self.assertIn("CreateRemoteThread", detections[0].matched_by)

    def test_empty_file_does_not_crash(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty.bin").write_bytes(b"")

            result = scan_path(root, self.store)

        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.detection_count, 0)

    def test_symlink_is_skipped_with_warning(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("os.symlink unavailable")

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_file = root / "real.txt"
            real_file.write_text("clean", encoding="utf-8")
            os.symlink(real_file, root / "link.txt")

            result = scan_path(root, self.store)

        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.skipped_file_count, 0)
        self.assertTrue(any("symbolic link" in warning.message for warning in result.warnings))


    def test_process_executor_detects_eicar(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "eicar.txt").write_text(EICAR_TEST_STRING, encoding="utf-8")
            (root / "clean.txt").write_text("clean", encoding="utf-8")

            result = scan_path(root, self.store, max_workers=2, executor="process")

        eicar_detections = [d for d in result.detections if d.threat_id == "EICAR.TEST.FILE"]
        self.assertEqual(result.scanned_file_count, 2)
        self.assertEqual(len(eicar_detections), 1)
        self.assertIn("md5", eicar_detections[0].matched_by)

    def test_report_writer_outputs_required_fields(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "scanme"
            root.mkdir()
            (root / "eicar.txt").write_text(EICAR_TEST_STRING, encoding="utf-8")
            report_path = Path(tmp) / "reports" / "scan.json"

            result = scan_path(root, self.store)
            write_json_report(result, report_path)
            payload = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["scanner"], "Sentinel")
        self.assertEqual(payload["summary"]["scanned_file_count"], 1)
        self.assertEqual(payload["summary"]["detection_count"], 1)
        self.assertTrue(payload["summary"]["infected_paths"])
        detection = payload["detections"][0]
        self.assertIn("infected_path", detection)
        self.assertIn("threat_name", detection)
        self.assertIn("severity", detection)
        self.assertIn("match_type", detection)
        self.assertIn("timestamp", detection)
        self.assertIn("benchmark", payload)


if __name__ == "__main__":
    unittest.main()
