from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterable

from .bloom import BloomFilter


VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class MalwareSignature:
    """A known malware signature loaded lazily from SQLite."""

    id: str
    name: str
    severity: str
    md5: str | None
    sha256: str | None
    hex_pattern: str | None
    pattern_bytes: bytes | None
    description: str


@dataclass(frozen=True)
class SignatureMatch:
    signature: MalwareSignature
    matched_by: tuple[str, ...]


class SignatureStore:
    """Bloom-filter backed SQLite store.

    Only the Bloom filter is loaded fully into memory. Signature metadata stays
    in SQLite and is queried only after a Bloom hit or during explicit pattern
    iteration.
    """

    def __init__(
        self,
        sqlite_path: str | Path,
        bloom_filter: BloomFilter,
        bloom_path: str | Path | None = None,
    ) -> None:
        self.sqlite_path = Path(sqlite_path)
        self.bloom_filter = bloom_filter
        self.bloom_path = Path(bloom_path) if bloom_path is not None else None
        self._local = threading.local()

    @property
    def source_path(self) -> Path:
        return self.sqlite_path

    def lookup_hashes(self, md5_digest: str, sha256_digest: str) -> list[SignatureMatch]:
        candidates: list[tuple[str, str]] = []
        if self.bloom_filter.might_contain(md5_digest):
            candidates.append(("md5", md5_digest.lower()))
        if self.bloom_filter.might_contain(sha256_digest):
            candidates.append(("sha256", sha256_digest.lower()))

        if not candidates:
            return []

        matched: dict[str, tuple[MalwareSignature, set[str]]] = {}
        connection = self._connection()

        for field, digest in candidates:
            rows = connection.execute(
                f"""
                SELECT id, name, severity, md5, sha256, hex_pattern, description
                FROM signatures
                WHERE {field} = ?
                """,
                (digest,),
            ).fetchall()

            for row in rows:
                signature = _signature_from_row(row)
                entry = matched.setdefault(signature.id, (signature, set()))
                entry[1].add(field)

        return [
            SignatureMatch(signature=signature, matched_by=tuple(sorted(fields)))
            for signature, fields in matched.values()
        ]

    def iter_pattern_signatures(self) -> Iterable[MalwareSignature]:
        rows = self._connection().execute(
            """
            SELECT id, name, severity, md5, sha256, hex_pattern, description
            FROM signatures
            WHERE hex_pattern IS NOT NULL AND trim(hex_pattern) != ''
            ORDER BY id
            """
        )

        for row in rows:
            yield _signature_from_row(row)

    def close(self) -> None:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()
            self._local.connection = None

    def _connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.sqlite_path)
            connection.row_factory = sqlite3.Row
            self._local.connection = connection
        return connection


def load_signature_store(sqlite_path: str | Path, bloom_path: str | Path) -> SignatureStore:
    return SignatureStore(
        sqlite_path=sqlite_path,
        bloom_filter=BloomFilter.load(bloom_path),
        bloom_path=bloom_path,
    )


def load_json_signatures(path: str | Path) -> list[MalwareSignature]:
    """Load and validate the source JSON used by build_db.py."""

    db_path = Path(path)
    with db_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    records = raw.get("signatures", raw) if isinstance(raw, dict) else raw
    if not isinstance(records, list):
        raise ValueError("signature database must be a list or contain a 'signatures' list")

    return [_signature_from_record(record) for record in records]


def write_sqlite_database(signatures: Iterable[MalwareSignature], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.exists():
        output.unlink()

    signature_rows = list(signatures)
    with sqlite3.connect(output) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE signatures (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                md5 TEXT,
                sha256 TEXT,
                hex_pattern TEXT,
                description TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX idx_signatures_md5 ON signatures(md5)")
        connection.execute("CREATE INDEX idx_signatures_sha256 ON signatures(sha256)")
        connection.execute("CREATE INDEX idx_signatures_hex_pattern ON signatures(hex_pattern)")
        connection.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        connection.executemany(
            """
            INSERT INTO signatures (id, name, severity, md5, sha256, hex_pattern, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    signature.id,
                    signature.name,
                    signature.severity,
                    signature.md5,
                    signature.sha256,
                    signature.hex_pattern,
                    signature.description,
                )
                for signature in signature_rows
            ],
        )


def iter_signature_hashes(signatures: Iterable[MalwareSignature]) -> Iterable[str]:
    for signature in signatures:
        if signature.md5:
            yield signature.md5
        if signature.sha256:
            yield signature.sha256


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


def _signature_from_row(row: sqlite3.Row) -> MalwareSignature:
    hex_pattern = row["hex_pattern"]
    pattern_bytes = _decode_hex_pattern(row["id"], hex_pattern) if hex_pattern else None
    return MalwareSignature(
        id=row["id"],
        name=row["name"],
        severity=row["severity"],
        md5=row["md5"],
        sha256=row["sha256"],
        hex_pattern=hex_pattern,
        pattern_bytes=pattern_bytes,
        description=row["description"],
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
