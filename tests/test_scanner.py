from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.scanner import scan_path, write_json_report  # noqa: E402
from sentinel.signatures import load_signature_database  # noqa: E402


EICAR_TEST_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = load_signature_database(PROJECT_ROOT / "data" / "signatures.json")

    def test_clean_folder_has_no_detections(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "clean.txt").write_text("ordinary class notes\n", encoding="utf-8")

            result = scan_path(root, self.database)

        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.detection_count, 0)
        self.assertEqual(result.skipped_file_count, 0)

    def test_eicar_in_nested_folder_is_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "a" / "b" / "c"
            nested.mkdir(parents=True)
            (nested / "eicar.txt").write_text(EICAR_TEST_STRING, encoding="utf-8")

            result = scan_path(root, self.database)

        eicar_detections = [d for d in result.detections if d.threat_id == "EICAR.TEST.FILE"]
        self.assertEqual(len(eicar_detections), 1)
        self.assertIn("md5", eicar_detections[0].matched_by)
        self.assertIn("sha256", eicar_detections[0].matched_by)

    def test_hex_pattern_mock_is_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mock.txt").write_text("prefix MALWARE_SIMULATION_PAYLOAD suffix", encoding="utf-8")

            result = scan_path(root, self.database)

        detections = [d for d in result.detections if d.threat_id == "MOCK.PATTERN.PAYLOAD"]
        self.assertEqual(len(detections), 1)
        self.assertIn("hex_pattern", detections[0].matched_by)

    def test_heuristic_api_sequence_is_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.txt").write_text(
                "VirtualAllocEx then WriteProcessMemory then CreateRemoteThread",
                encoding="utf-8",
            )

            result = scan_path(root, self.database)

        detections = [d for d in result.detections if d.threat_id == "HEUR.PROCESS.INJECTION"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "HIGH")
        self.assertEqual(detections[0].match_type, "heuristic")

    def test_empty_file_does_not_crash(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty.bin").write_bytes(b"")

            result = scan_path(root, self.database)

        self.assertEqual(result.scanned_file_count, 1)
        self.assertEqual(result.detection_count, 0)

    def test_report_writer_outputs_required_summary(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "scanme"
            root.mkdir()
            (root / "eicar.txt").write_text(EICAR_TEST_STRING, encoding="utf-8")
            report_path = Path(tmp) / "reports" / "scan.json"

            result = scan_path(root, self.database)
            write_json_report(result, report_path)
            payload = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["scanner"], "Sentinel")
        self.assertEqual(payload["summary"]["scanned_file_count"], 1)
        self.assertEqual(payload["summary"]["detection_count"], 1)
        self.assertTrue(payload["summary"]["infected_paths"])


if __name__ == "__main__":
    unittest.main()
