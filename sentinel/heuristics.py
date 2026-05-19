from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HeuristicRule:
    """A simple byte-string rule for suspicious behavior indicators."""

    id: str
    name: str
    severity: str
    indicators: tuple[str, ...]
    min_hits: int
    description: str

    def evaluate(self, content: bytes) -> list[str]:
        lowered = content.lower()
        matches: list[str] = []

        for indicator in self.indicators:
            needle = indicator.lower().encode("utf-8")
            if needle in lowered:
                matches.append(indicator)

        if len(matches) >= self.min_hits:
            return matches
        return []


DEFAULT_HEURISTIC_RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        id="HEUR.PROCESS.INJECTION",
        name="Suspicious process injection API sequence",
        severity="HIGH",
        indicators=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
        min_hits=2,
        description="Flags files containing multiple Windows APIs often used by process injection samples.",
    ),
    HeuristicRule(
        id="HEUR.SCRIPT.DOWNLOAD_EXEC",
        name="Suspicious script download and execution pattern",
        severity="MEDIUM",
        indicators=("powershell", "Invoke-WebRequest", "Start-Process", "DownloadString"),
        min_hits=2,
        description="Flags script-like content that appears to download and execute another payload.",
    ),
)
