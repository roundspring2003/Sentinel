from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Iterable

from .heuristics import DEFAULT_HEURISTIC_CONFIG, HeuristicConfig, analyze_file_heuristics, calculate_entropy
from .signatures import MalwareSignature, SignatureStore


CHUNK_SIZE = 8192


@dataclass
class Detection:
    path: str
    threat_id: str
    threat_name: str
    severity: str
    match_type: str
    matched_by: list[str]
    description: str
    timestamp: str
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "infected_path": self.path,
            "path": self.path,
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "severity": self.severity,
            "match_type": self.match_type,
            "timestamp": self.timestamp,
            "matched_by": self.matched_by,
            "description": self.description,
            "details": self.details,
        }


@dataclass
class ScanWarning:
    path: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message, "timestamp": self.timestamp, "level": "WARNING"}


@dataclass
class ScanResult:
    target: str
    signature_database: str | None
    started_at: str
    finished_at: str
    duration_seconds: float
    scanned_file_count: int
    skipped_file_count: int
    total_bytes_read: int
    detections: list[Detection]
    warnings: list[ScanWarning]

    @property
    def detection_count(self) -> int:
        return len(self.detections)

    @property
    def files_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.scanned_file_count / self.duration_seconds

    @property
    def megabytes_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return (self.total_bytes_read / (1024 * 1024)) / self.duration_seconds

    def to_dict(self) -> dict[str, object]:
        infected_paths = sorted({detection.path for detection in self.detections})
        return {
            "scanner": "Sentinel",
            "generated_at": self.finished_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 6),
            "target": self.target,
            "signature_database": self.signature_database,
            "summary": {
                "scanned_file_count": self.scanned_file_count,
                "skipped_file_count": self.skipped_file_count,
                "detection_count": self.detection_count,
                "warning_count": len(self.warnings),
                "total_bytes_read": self.total_bytes_read,
                "infected_paths": infected_paths,
            },
            "benchmark": {
                "files_per_second": round(self.files_per_second, 4),
                "megabytes_per_second": round(self.megabytes_per_second, 4),
            },
            "detections": [detection.to_dict() for detection in self.detections],
            "warnings": [warning.to_dict() for warning in self.warnings],
        }


@dataclass
class FileFeatures:
    md5: str
    sha256: str
    entropy: float
    bytes_read: int
    pattern_hits: list[MalwareSignature]


@dataclass
class FileScanOutcome:
    scanned_file_count: int = 0
    skipped_file_count: int = 0
    bytes_read: int = 0
    detections: list[Detection] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)


def scan_path(
    target: str | Path,
    signature_store: SignatureStore,
    heuristic_config: HeuristicConfig = DEFAULT_HEURISTIC_CONFIG,
    *,
    enable_heuristics: bool = True,
    enable_patterns: bool = True,
    max_workers: int | None = None,
) -> ScanResult:
    """Scan a file or directory without executing scanned files."""

    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"target does not exist: {target_path}")

    started_at = _utc_now()
    started_perf = time.perf_counter()
    walk_warnings: list[ScanWarning] = []
    pattern_signatures = tuple(signature_store.iter_pattern_signatures()) if enable_patterns else ()

    outcomes: list[FileScanOutcome] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for outcome in executor.map(
            lambda path: _scan_file(
                path,
                signature_store,
                pattern_signatures,
                heuristic_config,
                enable_heuristics,
            ),
            _iter_files(target_path, walk_warnings),
        ):
            outcomes.append(outcome)

    detections: list[Detection] = []
    warnings = list(walk_warnings)
    scanned_file_count = 0
    skipped_file_count = 0
    total_bytes_read = 0

    for outcome in outcomes:
        scanned_file_count += outcome.scanned_file_count
        skipped_file_count += outcome.skipped_file_count
        total_bytes_read += outcome.bytes_read
        detections.extend(outcome.detections)
        warnings.extend(outcome.warnings)

    detections.sort(key=lambda item: (item.path, item.threat_id, item.match_type))
    duration_seconds = time.perf_counter() - started_perf

    return ScanResult(
        target=str(target_path.resolve()),
        signature_database=str(signature_store.source_path),
        started_at=started_at,
        finished_at=_utc_now(),
        duration_seconds=duration_seconds,
        scanned_file_count=scanned_file_count,
        skipped_file_count=skipped_file_count,
        total_bytes_read=total_bytes_read,
        detections=detections,
        warnings=warnings,
    )


def compute_hashes(path: Path) -> tuple[str, str]:
    features = _read_file_features(path, ())
    return features.md5, features.sha256


def write_json_report(result: ScanResult, path: str | Path) -> None:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2)
        handle.write("\n")


def write_text_report(result: ScanResult, path: str | Path) -> None:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as handle:
        handle.write("Sentinel Scan Report\n")
        handle.write(f"Generated: {result.finished_at}\n")
        handle.write(f"Target: {result.target}\n")
        handle.write(f"Scanned files: {result.scanned_file_count}\n")
        handle.write(f"Skipped files: {result.skipped_file_count}\n")
        handle.write(f"Total bytes read: {result.total_bytes_read}\n")
        handle.write(f"Duration seconds: {result.duration_seconds:.4f}\n")
        handle.write(f"Files/sec: {result.files_per_second:.2f}\n")
        handle.write(f"MB/s: {result.megabytes_per_second:.2f}\n")
        handle.write(f"Detections: {result.detection_count}\n\n")

        if result.detections:
            handle.write("Detections\n")
            for detection in result.detections:
                matched_by = ", ".join(detection.matched_by)
                handle.write(
                    f"- [{detection.severity}] {detection.path}: "
                    f"{detection.threat_name} ({detection.match_type}: {matched_by})\n"
                )
        else:
            handle.write("No detections.\n")

        if result.warnings:
            handle.write("\nWarnings\n")
            for warning in result.warnings:
                handle.write(f"- {warning.path}: {warning.message}\n")


def _scan_file(
    file_path: Path,
    signature_store: SignatureStore,
    pattern_signatures: tuple[MalwareSignature, ...],
    heuristic_config: HeuristicConfig,
    enable_heuristics: bool,
) -> FileScanOutcome:
    display_path = str(file_path)
    if file_path.is_symlink():
        return FileScanOutcome(
            skipped_file_count=1,
            warnings=[ScanWarning(path=display_path, message="symbolic link skipped")],
        )

    try:
        features = _read_file_features(file_path, pattern_signatures)
    except PermissionError as exc:
        return FileScanOutcome(
            skipped_file_count=1,
            warnings=[ScanWarning(path=display_path, message=f"permission denied: {exc}")],
        )
    except OSError as exc:
        return FileScanOutcome(
            skipped_file_count=1,
            warnings=[ScanWarning(path=display_path, message=str(exc))],
        )

    detections = _match_signatures(display_path, features, signature_store)
    warnings: list[ScanWarning] = []

    if enable_heuristics:
        findings, heuristic_warnings = analyze_file_heuristics(
            file_path,
            entropy=features.entropy,
            total_bytes=features.bytes_read,
            config=heuristic_config,
        )
        detections.extend(_heuristic_detection(display_path, finding) for finding in findings)
        warnings.extend(ScanWarning(path=display_path, message=message) for message in heuristic_warnings)

    return FileScanOutcome(
        scanned_file_count=1,
        bytes_read=features.bytes_read,
        detections=detections,
        warnings=warnings,
    )


def _read_file_features(path: Path, pattern_signatures: Iterable[MalwareSignature]) -> FileFeatures:
    md5 = _new_md5()
    sha256 = hashlib.sha256()
    byte_counts = [0] * 256
    total_bytes = 0
    pattern_pairs = tuple(
        (signature, signature.pattern_bytes)
        for signature in pattern_signatures
        if signature.pattern_bytes
    )
    max_pattern_length = max((len(pattern) for _, pattern in pattern_pairs), default=0)
    overlap_size = max(0, max_pattern_length - 1)
    tail = b""
    pattern_hits: dict[str, MalwareSignature] = {}

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            md5.update(chunk)
            sha256.update(chunk)
            total_bytes += len(chunk)

            for value, count in Counter(chunk).items():
                byte_counts[value] += count

            if pattern_pairs:
                window = tail + chunk
                for signature, pattern in pattern_pairs:
                    if signature.id not in pattern_hits and pattern in window:
                        pattern_hits[signature.id] = signature
                tail = window[-overlap_size:] if overlap_size else b""

    return FileFeatures(
        md5=md5.hexdigest(),
        sha256=sha256.hexdigest(),
        entropy=calculate_entropy(byte_counts, total_bytes),
        bytes_read=total_bytes,
        pattern_hits=list(pattern_hits.values()),
    )


def _iter_files(target_path: Path, warnings: list[ScanWarning]) -> Iterable[Path]:
    if target_path.is_symlink():
        warnings.append(ScanWarning(path=str(target_path), message="symbolic link skipped"))
        return

    if target_path.is_file():
        yield target_path
        return

    for root, dirs, files in os.walk(
        target_path,
        topdown=True,
        followlinks=False,
        onerror=lambda exc: _record_walk_error(exc, warnings),
    ):
        root_path = Path(root)
        kept_dirs: list[str] = []
        for dirname in sorted(dirs):
            directory = root_path / dirname
            if directory.is_symlink():
                warnings.append(ScanWarning(path=str(directory), message="symbolic link directory skipped"))
            else:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs

        for file_name in sorted(files):
            file_path = root_path / file_name
            if file_path.is_symlink():
                warnings.append(ScanWarning(path=str(file_path), message="symbolic link file skipped"))
            else:
                yield file_path


def _record_walk_error(exc: OSError, warnings: list[ScanWarning]) -> None:
    path = exc.filename if exc.filename else "<unknown>"
    warnings.append(ScanWarning(path=str(path), message=str(exc)))


def _match_signatures(
    file_path: str,
    features: FileFeatures,
    signature_store: SignatureStore,
) -> list[Detection]:
    matches: dict[str, tuple[MalwareSignature, set[str]]] = {}

    for match in signature_store.lookup_hashes(features.md5, features.sha256):
        entry = matches.setdefault(match.signature.id, (match.signature, set()))
        entry[1].update(match.matched_by)

    for signature in features.pattern_hits:
        entry = matches.setdefault(signature.id, (signature, set()))
        entry[1].add("hex_pattern")

    detections: list[Detection] = []
    for signature_id in sorted(matches):
        signature, fields = matches[signature_id]
        detections.append(
            Detection(
                path=file_path,
                threat_id=signature.id,
                threat_name=signature.name,
                severity=signature.severity,
                match_type="Signature",
                matched_by=sorted(fields),
                description=signature.description,
                timestamp=_utc_now(),
            )
        )

    return detections


def _heuristic_detection(file_path: str, finding: object) -> Detection:
    return Detection(
        path=file_path,
        threat_id=finding.threat_id,
        threat_name=finding.threat_name,
        severity=finding.severity,
        match_type=finding.match_type,
        matched_by=list(finding.matched_by),
        description=finding.description,
        details=finding.details,
        timestamp=_utc_now(),
    )


def _new_md5() -> "hashlib._Hash":
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
