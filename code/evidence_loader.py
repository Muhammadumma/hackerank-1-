"""
evidence_loader.py - Non-Destructive Evidence Ingestion and Provenance Loader
HackerRank Orchestrate: Ghost Data Still Exists
"""

import csv
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from temporal_filter import parse_iso_timestamp

logger = logging.getLogger("evidence_loader")


@dataclass
class ManifestEntry:
    file_id: str
    file_path: str
    origin: str
    captured_at_raw: str
    captured_at: Optional[datetime]
    resolved_path: Path


@dataclass
class LoadedEvidence:
    file_id: str
    origin: str
    captured_at: Optional[datetime]
    file_type: str
    content: Any
    parse_errors: List[str] = field(default_factory=list)


class EvidenceLoader:
    def __init__(self, repo_root: Union[str, Path] = "."):
        self.repo_root = Path(repo_root)
        self.manifest_path = self.repo_root / "dataset" / "evidence_files.csv"
        self.manifest: Dict[str, ManifestEntry] = {}
        self.load_manifest()

    def load_manifest(self) -> Dict[str, ManifestEntry]:
        if not self.manifest_path.exists():
            return {}

        with open(self.manifest_path, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                f_id = row.get("file_id", "").strip()
                raw_path = row.get("file_path", "").strip()
                origin = row.get("origin", "").strip()
                cap_raw = row.get("captured_at", "").strip()
                resolved = self.repo_root / "dataset" / raw_path
                parsed_dt = parse_iso_timestamp(cap_raw)

                self.manifest[f_id] = ManifestEntry(
                    file_id=f_id,
                    file_path=raw_path,
                    origin=origin,
                    captured_at_raw=cap_raw,
                    captured_at=parsed_dt,
                    resolved_path=resolved,
                )
        return self.manifest

    def load_evidence(self, file_id: str) -> Optional[LoadedEvidence]:
        if file_id not in self.manifest:
            logger.warning(f"File ID {file_id} not found in manifest.")
            return None

        entry = self.manifest[file_id]
        path = entry.resolved_path
        if not path.exists():
            logger.warning(f"Resolved evidence file does not exist: {path}")
            return LoadedEvidence(file_id, entry.origin, entry.captured_at, "missing", None, ["File not found on disk"])

        # Path suffix routing (M083: inspects final extension for canonical dataset formats)
        suffix = path.suffix.lower()

        if suffix == ".sql":
            content, errors = self._load_sql(path)
            return LoadedEvidence(file_id, entry.origin, entry.captured_at, "sql", content, errors)
        elif suffix == ".json":
            content, errors = self._load_json(path)
            return LoadedEvidence(file_id, entry.origin, entry.captured_at, "json", content, errors)
        elif suffix in [".log", ".txt"]:
            content, errors = self._load_text(path)
            return LoadedEvidence(file_id, entry.origin, entry.captured_at, "log" if suffix == ".log" else "text", content, errors)
        else:
            content = {"file_path": str(path), "file_size": path.stat().st_size}
            return LoadedEvidence(file_id, entry.origin, entry.captured_at, "binary", content)

    def _load_sql(self, path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str]]:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        tables_data: Dict[str, List[Dict[str, Any]]] = {}
        errors: List[str] = []

        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(raw_text)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]
            for tbl in tables:
                cursor.execute(f"PRAGMA table_info('{tbl}');")
                cols = [c[1] for c in cursor.fetchall()]
                cursor.execute(f"SELECT * FROM '{tbl}';")
                tables_data[tbl] = [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            errors.append(f"SQL execution warning: {e}")
        finally:
            conn.close()

        return tables_data, errors

    def _load_json(self, path: Path) -> Tuple[Any, List[str]]:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        errors: List[str] = []
        try:
            data = json.loads(raw_text)
        except Exception as e:
            logger.error(f"Failed to parse JSON file {path}: {e}")
            errors.append(f"JSON parse error: {e}")
            data = {}
        return data, errors

    def _load_text(self, path: Path) -> Tuple[List[str], List[str]]:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines, []
