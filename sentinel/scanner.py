from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

from .heuristics import DEFAULT_HEURISTIC_RULES, HeuristicRule
from .signatures import MalwareSignature, SignatureDatabase


CHUNK_SIZE = 1024 * 1024


@dataclass
class Detection:
    path: str
    threat_id: str
    threat_name: str
    severity: str
    match_type: str
    matched_by: list[str]
    description: str
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "severity": self.severity,
            "match_type": self.match_type,
            "matched_by": self.matched_by,
            "description": self.description,
            "details": self.details,
        }


@dataclass
class ScanWarning:
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message}


@dataclass
class ScanResult:
    target: str
    signature_database: str | None
    started_at: str
    finished_at: str
    scanned_file_count: int
    skipped_file_count: int
    detections: list[Detection]
    warnings: list[ScanWarning]

    @property
    def detection_count(self) -> int:
        return len(self.detections)

    def to_dict(self) -> dict[str, object]:
        infected_paths = sorted({detection.path for detection in self.detections})
        return {
            "scanner": "Sentinel",
            "generated_at": self.finished_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target": self.target,
            "signature_database": self.signature_database,
            "summary": {
                "scanned_file_count": self.scanned_file_count,
                "skipped_file_count": self.skipped_file_count,
                "detection_count": self.detection_count,
                "warning_count": len(self.warnings),
                "infected_paths": infected_paths,
            },
            "detections": [detection.to_dict() for detection in self.detections],
            "warnings": [warning.to_dict() for warning in self.warnings],
        }


def scan_path(
    target: str | Path,
    database: SignatureDatabase,
    heuristic_rules: Iterable[HeuristicRule] = DEFAULT_HEURISTIC_RULES,
) -> ScanResult:
    """Scan a file or directory without executing any scanned files."""

    target_path = Path(target)
    started_at = _utc_now()
    scanned_file_count = 0
    skipped_file_count = 0
    detections: list[Detection] = []
    warnings: list[ScanWarning] = []

    if not target_path.exists():
        raise FileNotFoundError(f"target does not exist: {target_path}")

    for file_path in _iter_files(target_path, warnings):
        display_path = str(file_path)

        try:
            md5_digest, sha256_digest = compute_hashes(file_path)
            content = file_path.read_bytes()
        except OSError as exc:
            skipped_file_count += 1
            warnings.append(ScanWarning(path=display_path, message=str(exc)))
            continue

        scanned_file_count += 1
        detections.extend(
            _match_signatures(
                file_path=display_path,
                content=content,
                md5_digest=md5_digest,
                sha256_digest=sha256_digest,
                database=database,
            )
        )
        detections.extend(_match_heuristics(display_path, content, heuristic_rules))

    return ScanResult(
        target=str(target_path.resolve()),
        signature_database=str(database.source_path) if database.source_path else None,
        started_at=started_at,
        finished_at=_utc_now(),
        scanned_file_count=scanned_file_count,
        skipped_file_count=skipped_file_count,
        detections=detections,
        warnings=warnings,
    )


def compute_hashes(path: Path) -> tuple[str, str]:
    md5 = _new_md5()
    sha256 = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


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


def _iter_files(target_path: Path, warnings: list[ScanWarning]) -> Iterable[Path]:
    if target_path.is_file():
        yield target_path
        return

    for root, dirs, files in os.walk(target_path, onerror=lambda exc: _record_walk_error(exc, warnings)):
        dirs.sort()
        for file_name in sorted(files):
            yield Path(root) / file_name


def _record_walk_error(exc: OSError, warnings: list[ScanWarning]) -> None:
    path = exc.filename if exc.filename else "<unknown>"
    warnings.append(ScanWarning(path=str(path), message=str(exc)))


def _match_signatures(
    file_path: str,
    content: bytes,
    md5_digest: str,
    sha256_digest: str,
    database: SignatureDatabase,
) -> list[Detection]:
    matches: dict[str, set[str]] = {}

    for signature in database.match_sha256(sha256_digest):
        matches.setdefault(signature.id, set()).add("sha256")
    for signature in database.match_md5(md5_digest):
        matches.setdefault(signature.id, set()).add("md5")
    for signature in database.patterns:
        if signature.pattern_bytes and signature.pattern_bytes in content:
            matches.setdefault(signature.id, set()).add("hex_pattern")

    detections: list[Detection] = []
    for signature_id in sorted(matches):
        signature = database.by_id[signature_id]
        detections.append(_signature_detection(file_path, signature, sorted(matches[signature_id])))

    return detections


def _signature_detection(file_path: str, signature: MalwareSignature, matched_by: list[str]) -> Detection:
    return Detection(
        path=file_path,
        threat_id=signature.id,
        threat_name=signature.name,
        severity=signature.severity,
        match_type="signature",
        matched_by=matched_by,
        description=signature.description,
    )


def _match_heuristics(
    file_path: str,
    content: bytes,
    heuristic_rules: Iterable[HeuristicRule],
) -> list[Detection]:
    detections: list[Detection] = []

    for rule in heuristic_rules:
        indicators = rule.evaluate(content)
        if not indicators:
            continue

        detections.append(
            Detection(
                path=file_path,
                threat_id=rule.id,
                threat_name=rule.name,
                severity=rule.severity,
                match_type="heuristic",
                matched_by=["indicator_strings"],
                description=rule.description,
                details={"matched_indicators": indicators},
            )
        )

    return detections


def _new_md5() -> "hashlib._Hash":
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
