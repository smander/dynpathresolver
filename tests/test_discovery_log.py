"""Tests for DiscoveryLog."""

import pytest
import json
import sqlite3
from dynpathresolver.core.discovery_log import DiscoveryLog


class TestDiscoveryLog:
    def test_add_entry(self):
        log = DiscoveryLog()
        log.add({
            'source': 0x401000,
            'target': 0x401100,
            'type': 'indirect_jump',
            'confidence': 1.0,
        })
        assert len(log.entries) == 1
        assert log.entries[0]['source'] == 0x401000

    def test_export_json(self, tmp_path):
        log = DiscoveryLog()
        log.add({
            'source': 0x401000,
            'target': 0x401100,
            'type': 'indirect_jump',
        })

        out_file = tmp_path / "discoveries.json"
        log.export_json(str(out_file))

        data = json.loads(out_file.read_text())
        assert len(data) == 1
        assert data[0]['source'] == 0x401000

    def test_export_sqlite(self, tmp_path):
        log = DiscoveryLog()
        log.add({
            'source': 0x401000,
            'target': 0x401100,
            'type': 'indirect_jump',
            'confidence': 0.9,
            'solver_solutions': [0x401100, 0x401200],
        })

        db_file = tmp_path / "discoveries.db"
        log.export_sqlite(str(db_file))

        conn = sqlite3.connect(str(db_file))
        cursor = conn.execute("SELECT source_addr, target_addr, resolution_type FROM resolutions")
        row = cursor.fetchone()
        assert row == (0x401000, 0x401100, 'indirect_jump')
        conn.close()

    def test_duplicate_entries_ignored(self):
        log = DiscoveryLog()
        log.add({'source': 0x401000, 'target': 0x401100, 'type': 'indirect_jump'})
        log.add({'source': 0x401000, 'target': 0x401100, 'type': 'indirect_jump'})
        assert len(log.entries) == 1
