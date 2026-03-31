"""Discovery log for recording resolved paths."""

import json
import sqlite3
import time
from typing import Any


class DiscoveryLog:
    """Dual-format storage for resolution records."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS resolutions (
            id INTEGER PRIMARY KEY,
            source_addr INTEGER NOT NULL,
            target_addr INTEGER NOT NULL,
            resolution_type TEXT NOT NULL,
            timestamp REAL,
            confidence REAL,
            solver_solutions TEXT,
            backtrack_depth INTEGER,
            library_loaded TEXT,
            UNIQUE(source_addr, target_addr, resolution_type)
        );

        CREATE INDEX IF NOT EXISTS idx_source ON resolutions(source_addr);
        CREATE INDEX IF NOT EXISTS idx_type ON resolutions(resolution_type);
        CREATE INDEX IF NOT EXISTS idx_library ON resolutions(library_loaded);
    """

    def __init__(self):
        self.entries: list[dict[str, Any]] = []
        self._seen: set[tuple[int, int, str]] = set()

    def add(self, entry: dict[str, Any]) -> bool:
        """Add a resolution entry. Returns False if duplicate."""
        key = (entry['source'], entry['target'], entry['type'])
        if key in self._seen:
            return False

        self._seen.add(key)
        entry.setdefault('timestamp', time.time())
        self.entries.append(entry)
        return True

    def export_json(self, path: str) -> None:
        """Export entries to JSON file."""
        with open(path, 'w') as f:
            json.dump(self.entries, f, indent=2)

    def export_sqlite(self, path: str) -> None:
        """Export entries to SQLite database."""
        conn = sqlite3.connect(path)
        conn.executescript(self.SCHEMA)

        for entry in self.entries:
            solutions_json = json.dumps(entry.get('solver_solutions', []))
            conn.execute(
                """INSERT OR IGNORE INTO resolutions
                   (source_addr, target_addr, resolution_type, timestamp,
                    confidence, solver_solutions, backtrack_depth, library_loaded)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry['source'],
                    entry['target'],
                    entry['type'],
                    entry.get('timestamp'),
                    entry.get('confidence'),
                    solutions_json,
                    entry.get('backtrack_depth'),
                    entry.get('library_loaded'),
                )
            )
        conn.commit()
        conn.close()

    def close(self) -> None:
        """Close any open resources (no-op, connections are scoped to export methods)."""

    def __enter__(self) -> "DiscoveryLog":
        return self

    def __exit__(self, *args) -> None:
        self.close()
