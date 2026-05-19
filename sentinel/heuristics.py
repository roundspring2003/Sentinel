from __future__ import annotations

from dataclasses import dataclass, field
from math import log2
from pathlib import Path

try:  # Optional at runtime; listed in pyproject for full PE IAT support.
    import pefile  # type: ignore
except ImportError:  # pragma: no cover - depends on local environment
    pefile = None  # type: ignore


@dataclass(frozen=True)
class HeuristicConfig:
    suspicious_apis: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"}
        )
    )
    api_min_hits: int = 2
    entropy_threshold: float = 7.5
    entropy_min_size: int = 1024


@dataclass(frozen=True)
class HeuristicFinding:
    threat_id: str
    threat_name: str
    severity: str
    match_type: str
    matched_by: tuple[str, ...]
    description: str
    details: dict[str, object]


DEFAULT_HEURISTIC_CONFIG = HeuristicConfig()


def calculate_entropy(byte_counts: list[int], total_bytes: int) -> float:
    if total_bytes <= 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / total_bytes
        entropy -= probability * log2(probability)
    return entropy


def analyze_file_heuristics(
    path: Path,
    entropy: float,
    total_bytes: int,
    config: HeuristicConfig = DEFAULT_HEURISTIC_CONFIG,
) -> tuple[list[HeuristicFinding], list[str]]:
    findings: list[HeuristicFinding] = []
    warnings: list[str] = []

    if total_bytes >= config.entropy_min_size and entropy >= config.entropy_threshold:
        severity = "MEDIUM" if entropy >= 7.8 else "LOW"
        findings.append(
            HeuristicFinding(
                threat_id="HEUR.ENTROPY.HIGH",
                threat_name="High entropy packed or encrypted content",
                severity=severity,
                match_type="Heuristic_Entropy",
                matched_by=("shannon_entropy",),
                description="File byte distribution is highly random, which can indicate packing or encryption.",
                details={"entropy": round(entropy, 4), "threshold": config.entropy_threshold},
            )
        )

    if not _is_pe_candidate(path):
        return findings, warnings

    if pefile is None:
        warnings.append("pefile is not installed; PE IAT heuristic skipped")
        return findings, warnings

    try:
        imported_apis = extract_pe_imports(path)
    except Exception as exc:  # pefile may raise several parse-specific exceptions.
        warnings.append(f"PE IAT heuristic skipped: {exc}")
        return findings, warnings

    suspicious = sorted(config.suspicious_apis.intersection(imported_apis))
    if len(suspicious) >= config.api_min_hits:
        severity = "HIGH" if len(suspicious) >= 3 else "MEDIUM"
        findings.append(
            HeuristicFinding(
                threat_id="HEUR.PE.IAT.SUSPICIOUS_API",
                threat_name="Suspicious PE import address table APIs",
                severity=severity,
                match_type="Heuristic_API",
                matched_by=tuple(suspicious),
                description="PE imports include APIs commonly associated with process injection.",
                details={"suspicious_apis": suspicious, "import_count": len(imported_apis)},
            )
        )

    return findings, warnings


def extract_pe_imports(path: Path) -> set[str]:
    if pefile is None:
        return set()

    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imported: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imported_symbol in getattr(entry, "imports", []):
                if imported_symbol.name:
                    imported.add(imported_symbol.name.decode("utf-8", errors="ignore"))
        return imported
    finally:
        close = getattr(pe, "close", None)
        if close:
            close()


def _is_pe_candidate(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False
