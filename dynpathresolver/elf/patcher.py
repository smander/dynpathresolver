"""CFG patcher for recording and integrating resolved paths."""

import os
from typing import TYPE_CHECKING, Any

from dynpathresolver.core.discovery_log import DiscoveryLog

if TYPE_CHECKING:
    import angr


class CFGPatcher:
    """Records resolved paths and integrates with angr's CFG."""

    def __init__(self, project: "angr.Project"):
        self.project = project
        self.discovery_log = DiscoveryLog()

    def record_resolution(
        self,
        source_addr: int,
        target_addr: int,
        resolution_type: str,
        metadata: dict[str, Any],
    ) -> None:
        """Record a resolved control flow edge."""
        entry = {
            'source': source_addr,
            'target': target_addr,
            'type': resolution_type,
            'confidence': metadata.get('confidence', 1.0),
            'solver_solutions': metadata.get('all_solutions', []),
            'backtrack_depth': metadata.get('backtrack_depth'),
            'library_loaded': metadata.get('library'),
        }
        self.discovery_log.add(entry)

        # Attempt to add edge to angr's CFG if available
        self._try_add_cfg_edge(source_addr, target_addr, resolution_type)

    def _try_add_cfg_edge(
        self, source_addr: int, target_addr: int, resolution_type: str
    ) -> bool:
        """Try to add an edge to angr's CFG. Returns True if successful."""
        if not hasattr(self.project, 'kb'):
            return False

        if not hasattr(self.project.kb, 'cfgs') or not self.project.kb.cfgs:
            return False

        try:
            cfg = self.project.kb.cfgs.get_most_accurate()
            if cfg is None:
                return False

            jumpkind = 'Ijk_Call' if 'call' in resolution_type else 'Ijk_Boring'

            src_node = cfg.get_any_node(source_addr)
            dst_node = cfg.get_any_node(target_addr)

            if src_node and dst_node:
                cfg.graph.add_edge(
                    src_node, dst_node,
                    jumpkind=jumpkind,
                    dynamic_resolved=True
                )
                return True
        except Exception:
            pass

        return False

    def export_results(self, output_dir: str) -> None:
        """Export discovery log to JSON and SQLite files."""
        os.makedirs(output_dir, exist_ok=True)
        self.discovery_log.export_json(os.path.join(output_dir, 'discoveries.json'))
        self.discovery_log.export_sqlite(os.path.join(output_dir, 'discoveries.db'))

