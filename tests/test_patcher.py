"""Tests for CFGPatcher."""

import pytest


class TestCFGPatcher:
    def test_init(self, angr_project):
        """Test patcher initialization."""
        from dynpathresolver.elf.patcher import CFGPatcher

        patcher = CFGPatcher(angr_project)

        assert patcher.project == angr_project
        assert len(patcher.discovery_log.entries) == 0

    def test_record_resolution(self, angr_project):
        """Test recording a resolution."""
        from dynpathresolver.elf.patcher import CFGPatcher

        patcher = CFGPatcher(angr_project)

        patcher.record_resolution(
            source_addr=0x401000,
            target_addr=0x401100,
            resolution_type='indirect_jump',
            metadata={'confidence': 0.9}
        )

        assert len(patcher.discovery_log.entries) == 1
        entry = patcher.discovery_log.entries[0]
        assert entry['source'] == 0x401000
        assert entry['target'] == 0x401100
        assert entry['confidence'] == 0.9

    def test_record_multiple_resolutions(self, angr_project):
        """Test recording multiple resolutions."""
        from dynpathresolver.elf.patcher import CFGPatcher

        patcher = CFGPatcher(angr_project)

        patcher.record_resolution(0x401000, 0x401100, 'indirect_jump', {})
        patcher.record_resolution(0x401000, 0x401200, 'indirect_jump', {})
        patcher.record_resolution(0x402000, 0x402100, 'vtable_call', {})

        assert len(patcher.discovery_log.entries) == 3

    def test_export_results(self, angr_project, tmp_path):
        """Test exporting results to files."""
        from dynpathresolver.elf.patcher import CFGPatcher

        patcher = CFGPatcher(angr_project)
        patcher.record_resolution(0x401000, 0x401100, 'indirect_jump', {})

        json_path = tmp_path / "discoveries.json"
        db_path = tmp_path / "discoveries.db"

        patcher.export_results(str(tmp_path))

        assert json_path.exists()
        assert db_path.exists()
