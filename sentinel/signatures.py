from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass(frozen=True)
class MalwareSignature:
    """A known malware signature loaded from the JSON database."""

    id: str
    name: str
    severity: str
    md5: str | None
    sha256: str | None
    hex_pattern: str | None
    pattern_bytes: bytes | None
    description: str


class SignatureDatabase:
    """In-memory indexes for hash and byte-pattern signature matching."""

    def __init__(self, signatures: list[MalwareSignature], source_path: Path | None = None) -> None:
        self.signatures = signatures
        self.source_path = source_path
        self.by_id: dict[str, MalwareSignature] = {}
        self.md5_map: dict[str, list[MalwareSignature]] = {}
        self.sha256_map: dict[str, list[MalwareSignature]] = {}
        self.patterns: list[MalwareSignature] = []

        for signature in signatures:
            if signature.id in self.by_id:
                raise ValueError(f"duplicate signature id: {signature.id}")
            self.by_id[signature.id] = signature

            if signature.md5:
                self.md5_map.setdefault(signature.md5, []).append(signature)
            if signature.sha256:
                self.sha256_map.setdefault(signature.sha256, []).append(signature)
            if signature.pattern_bytes:
                self.patterns.append(signature)

    def match_md5(self, digest: str) -> list[MalwareSignature]:
        return self.md5_map.get(digest.lower(), [])

    def match_sha256(self, digest: str) -> list[MalwareSignature]:
        return self.sha256_map.get(digest.lower(), [])


def load_signature_database(path: str | Path) -> SignatureDatabase:
    """Load a JSON signature database and build lookup indexes."""

    db_path = Path(path)
    with db_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    records = raw.get("signatures", raw) if isinstance(raw, dict) else raw
    if not isinstance(records, list):
        raise ValueError("signature database must be a list or contain a 'signatures' list")

    signatures = [_signature_from_record(record) for record in records]
    return SignatureDatabase(signatures, source_path=db_path)


def _signature_from_record(record: Any) -> MalwareSignature:
    if not isinstance(record, dict):
        raise ValueError("each signature entry must be an object")

    signature_id = _required_text(record, "id")
    name = _required_text(record, "name")
    severity = _required_text(record, "severity").upper()
    description = _required_text(record, "description")

    if severity not in VALID_SEVERITIES:
        raise ValueError(f"{signature_id}: invalid severity {severity!r}")

    md5 = _optional_digest(record, "md5", 32)
    sha256 = _optional_digest(record, "sha256", 64)
    hex_pattern = _optional_text(record, "hex_pattern")
    pattern_bytes = _decode_hex_pattern(signature_id, hex_pattern) if hex_pattern else None

    if not (md5 or sha256 or pattern_bytes):
        raise ValueError(f"{signature_id}: at least one md5, sha256, or hex_pattern is required")

    return MalwareSignature(
        id=signature_id,
        name=name,
        severity=severity,
        md5=md5,
        sha256=sha256,
        hex_pattern=hex_pattern,
        pattern_bytes=pattern_bytes,
        description=description,
    )


def _required_text(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"signature field {key!r} is required")
    return value.strip()


def _optional_text(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"signature field {key!r} must be a string")
    text = value.strip()
    return text or None


def _optional_digest(record: dict[str, Any], key: str, expected_length: int) -> str | None:
    value = _optional_text(record, key)
    if value is None:
        return None

    digest = value.lower()
    if len(digest) != expected_length or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{record.get('id', '<unknown>')}: {key} must be {expected_length} hex chars")
    return digest


def _decode_hex_pattern(signature_id: str, hex_pattern: str) -> bytes:
    try:
        pattern = bytes.fromhex(hex_pattern)
    except ValueError as exc:
        raise ValueError(f"{signature_id}: invalid hex_pattern") from exc

    if not pattern:
        raise ValueError(f"{signature_id}: hex_pattern must not be empty")
    return pattern
