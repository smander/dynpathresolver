"""Configuration dataclass for DynPathResolver.

Houses ``DynPathResolverConfig``, the central dataclass that controls
analysis options such as forking limits, platform, and feature toggles.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DynPathResolverConfig:
    """Configuration for DynPathResolver analysis technique."""
    max_forks: int = 8
    preload_common: bool = True
    library_paths: list[str] = field(default_factory=list)
    vtable_backtrack_limit: int = 1000
    output_dir: str | None = None
    directed_mode: bool = False
    platform: str = 'auto'
    path_predictor: str = 'heuristic'
    handle_unpacking: bool = False
    validation_mode: str = 'none'
    handle_syscall_loading: bool = False
    track_indirect_flow: bool = False
    detect_rop: bool = False
    detect_jop: bool = False
    track_signals: bool = False
    track_environment: bool = False
    track_ifunc: bool = False
    track_init_fini: bool = False
    track_process_exec: bool = False
    track_security_policy: bool = False
    enable_taint_tracking: bool = False
    enable_decryption_detection: bool = False
    enable_stage_tracking: bool = False
