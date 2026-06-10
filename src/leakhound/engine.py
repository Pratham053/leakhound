from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional

from leakhound.detectors.base import Detector
from leakhound.models import Finding

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             "dist", "build", ".idea", ".mypy_cache", ".pytest_cache"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # skip files larger than 5 MB


class Scanner:
    """Walks a path, runs every detector on each text file, collects Findings."""

    def __init__(self, detectors: list[Detector]) -> None:
        self.detectors = detectors

    def scan_path(self, root: str) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in self._iter_files(Path(root)):
            content = self._read_text(file_path)
            if content is None:
                continue
            for detector in self.detectors:
                findings.extend(detector.scan(str(file_path), content))
        return findings

    def _iter_files(self, root: Path) -> Iterable[Path]:
        if root.is_file():
            yield root
            return
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                yield Path(dirpath) / name

    @staticmethod
    def _read_text(path: Path) -> Optional[str]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return None
            return path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            return None  # binary/unreadable files are skipped, not errors