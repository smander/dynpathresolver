"""
Control flow tracking and analysis for detecting code execution in dynamic memory.

This module provides:
1. IndirectFlowTracker - Tracks indirect calls/jumps to dynamically mapped memory
2. RopDetector - Detects Return-Oriented Programming patterns
3. JopDetector - Detects Jump-Oriented Programming patterns
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from collections import deque

import angr

if TYPE_CHECKING:
    from dynpathresolver.tracking.memory_tracker import MemoryRegionTracker

log = logging.getLogger(__name__)


@dataclass
class IndirectFlowEvent:
    """Represents an indirect control flow event."""

    event_type: str  # 'call', 'jump', 'return'
    source_addr: int
    target_addr: int
    is_dynamic_target: bool = False
    is_symbolic_target: bool = False
    step: int = 0
    context: dict = field(default_factory=dict)


@dataclass
class RopGadget:
    """Represents a ROP gadget."""

    addr: int
    instructions: list[str]
    gadget_type: str  # 'ret', 'call', 'syscall', 'jop_dispatch'
    length: int = 0


@dataclass
class RopChain:
    """Represents a detected ROP chain."""

    gadgets: list[RopGadget]
    start_addr: int
    detected_at_step: int
    confidence: float = 0.0


@dataclass
class JopGadget:
    """Represents a JOP gadget."""

    addr: int
    instructions: list[str]
    gadget_type: str  # 'dispatcher', 'functional', 'data_loader'
    target_reg: str | None = None


@dataclass
class JopChain:
    """Represents a detected JOP chain."""

    dispatcher: JopGadget | None
    gadgets: list[JopGadget]
    detected_at_step: int
    confidence: float = 0.0


class IndirectFlowTracker:
    """
    Tracks indirect control flow to detect code execution in dynamic memory.

    This class:
    1. Monitors indirect calls (call reg, call [mem])
    2. Monitors indirect jumps (jmp reg, jmp [mem])
    3. Monitors returns (ret)
    4. Correlates with MemoryRegionTracker to identify dynamic targets
    5. Records events for later analysis
    """

    def __init__(self, project: "angr.Project",
                 memory_tracker: "MemoryRegionTracker | None" = None):
        self.project = project
        self.memory_tracker = memory_tracker

        # Event tracking
        self.events: list[IndirectFlowEvent] = []
        self.dynamic_calls: list[IndirectFlowEvent] = []
        self.dynamic_jumps: list[IndirectFlowEvent] = []

        # Return address tracking for ROP detection
        self.return_addresses: deque[int] = deque(maxlen=100)
        self.return_targets: list[tuple[int, int]] = []  # (ret_addr, target)

        # Statistics
        self.total_indirect_calls: int = 0
        self.total_indirect_jumps: int = 0
        self.total_returns: int = 0

    def attach(self, state: "angr.SimState") -> None:
        """Attach breakpoints to a simulation state."""
        # Monitor function calls
        state.inspect.b('call', when=angr.BP_BEFORE, action=self._on_call)

        # Monitor jumps/branches (exit events)
        state.inspect.b('exit', when=angr.BP_BEFORE, action=self._on_exit)

        # Monitor returns
        state.inspect.b('return', when=angr.BP_BEFORE, action=self._on_return)

    def _on_call(self, state: "angr.SimState") -> None:
        """Callback for call events."""
        self.total_indirect_calls += 1

        try:
            target = state.inspect.function_address
            source = state.addr

            # Check if target is symbolic
            is_symbolic = state.solver.symbolic(target)

            if is_symbolic:
                # Try to concretize
                if state.solver.satisfiable():
                    target_val = state.solver.eval(target)
                else:
                    target_val = 0
            else:
                target_val = state.solver.eval(target)

            # Check if target is in dynamically mapped memory
            is_dynamic = False
            if self.memory_tracker and target_val:
                is_dynamic = self.memory_tracker.is_dynamically_mapped(target_val)

            event = IndirectFlowEvent(
                event_type='call',
                source_addr=source,
                target_addr=target_val,
                is_dynamic_target=is_dynamic,
                is_symbolic_target=is_symbolic,
                step=state.history.depth if state.history else 0,
            )

            self.events.append(event)

            if is_dynamic:
                self.dynamic_calls.append(event)
                log.info(f"Call to dynamic memory: 0x{source:x} -> 0x{target_val:x}")

        except Exception as e:
            log.debug(f"Error in _on_call: {e}")

    def _on_exit(self, state: "angr.SimState") -> None:
        """Callback for exit (jump/branch) events."""
        self.total_indirect_jumps += 1

        try:
            # Get the jump target (instruction pointer after the jump)
            target = state.regs.ip
            source = state.history.addr if state.history else state.addr

            # Check if target is symbolic
            is_symbolic = state.solver.symbolic(target)

            if is_symbolic:
                if state.solver.satisfiable():
                    target_val = state.solver.eval(target)
                else:
                    target_val = 0
            else:
                target_val = state.solver.eval(target)

            # Check if target is in dynamically mapped memory
            is_dynamic = False
            if self.memory_tracker and target_val:
                is_dynamic = self.memory_tracker.is_dynamically_mapped(target_val)

            # Only record if it looks like an indirect jump
            # (symbolic or dynamic target)
            if is_symbolic or is_dynamic:
                event = IndirectFlowEvent(
                    event_type='jump',
                    source_addr=source,
                    target_addr=target_val,
                    is_dynamic_target=is_dynamic,
                    is_symbolic_target=is_symbolic,
                    step=state.history.depth if state.history else 0,
                )

                self.events.append(event)

                if is_dynamic:
                    self.dynamic_jumps.append(event)
                    log.info(f"Jump to dynamic memory: 0x{source:x} -> 0x{target_val:x}")

        except Exception as e:
            log.debug(f"Error in _on_exit: {e}")

    def _on_return(self, state: "angr.SimState") -> None:
        """Callback for return events."""
        self.total_returns += 1

        try:
            # Get return address from stack
            sp = state.regs.sp
            if state.solver.symbolic(sp):
                return

            sp_val = state.solver.eval(sp)
            ret_addr = state.memory.load(sp_val, state.arch.bytes,
                                         endness=state.arch.memory_endness)

            if state.solver.symbolic(ret_addr):
                ret_addr_val = state.solver.eval(ret_addr) if state.solver.satisfiable() else 0
            else:
                ret_addr_val = state.solver.eval(ret_addr)

            # Track for ROP detection
            self.return_addresses.append(ret_addr_val)
            self.return_targets.append((state.addr, ret_addr_val))

            # Check if returning to dynamic memory
            is_dynamic = False
            if self.memory_tracker and ret_addr_val:
                is_dynamic = self.memory_tracker.is_dynamically_mapped(ret_addr_val)

            if is_dynamic:
                event = IndirectFlowEvent(
                    event_type='return',
                    source_addr=state.addr,
                    target_addr=ret_addr_val,
                    is_dynamic_target=True,
                    step=state.history.depth if state.history else 0,
                )
                self.events.append(event)
                log.warning(f"Return to dynamic memory: 0x{state.addr:x} -> "
                           f"0x{ret_addr_val:x}")

        except Exception as e:
            log.debug(f"Error in _on_return: {e}")

    # === Query Methods ===

    def get_dynamic_calls(self) -> list[IndirectFlowEvent]:
        """Get all calls to dynamically mapped memory."""
        return self.dynamic_calls.copy()

    def get_dynamic_jumps(self) -> list[IndirectFlowEvent]:
        """Get all jumps to dynamically mapped memory."""
        return self.dynamic_jumps.copy()

    def get_all_events(self) -> list[IndirectFlowEvent]:
        """Get all recorded events."""
        return self.events.copy()

    def has_dynamic_execution(self) -> bool:
        """Check if any code execution in dynamic memory was detected."""
        return len(self.dynamic_calls) > 0 or len(self.dynamic_jumps) > 0

    def get_statistics(self) -> dict:
        """Get tracking statistics."""
        return {
            'total_indirect_calls': self.total_indirect_calls,
            'total_indirect_jumps': self.total_indirect_jumps,
            'total_returns': self.total_returns,
            'dynamic_calls': len(self.dynamic_calls),
            'dynamic_jumps': len(self.dynamic_jumps),
            'total_events': len(self.events),
        }

    def reset(self):
        """Reset all tracking state."""
        self.events.clear()
        self.dynamic_calls.clear()
        self.dynamic_jumps.clear()
        self.return_addresses.clear()
        self.return_targets.clear()
        self.total_indirect_calls = 0
        self.total_indirect_jumps = 0
        self.total_returns = 0


class RopDetector:
    """
    Detects Return-Oriented Programming patterns.

    ROP detection is based on:
    1. Tracking return addresses during execution
    2. Identifying gadget-like instruction sequences (short sequences ending in ret)
    3. Detecting unusual return patterns (multiple consecutive returns)
    4. Correlating with dynamically mapped memory
    """

    def __init__(self, project: "angr.Project",
                 memory_tracker: "MemoryRegionTracker | None" = None):
        self.project = project
        self.memory_tracker = memory_tracker

        # Pre-discovered gadgets
        self.gadgets: dict[int, RopGadget] = {}

        # Detection results
        self.detected_chains: list[RopChain] = []

        # Configuration
        self.max_gadget_length = 10  # Max instructions per gadget
        self.min_chain_length = 3    # Min gadgets to consider a chain

        # Cached Capstone disassembler instance
        self._cs = self._create_capstone()

    def _create_capstone(self):
        """Create a Capstone disassembler for the project architecture."""
        try:
            import capstone
        except ImportError:
            return None
        arch_name = self.project.arch.name
        if arch_name in ('AMD64', 'X86_64', 'X86'):
            mode = capstone.CS_MODE_64 if self.project.arch.bits == 64 else capstone.CS_MODE_32
            cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        elif arch_name == 'AARCH64':
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif arch_name in ('ARM', 'ARMEL', 'ARMHF'):
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            return None
        cs.detail = True
        return cs

    def find_gadgets(self) -> dict[int, RopGadget]:
        """
        Pre-analyze binary to find potential ROP gadgets.

        Returns dict mapping address to RopGadget.
        """
        if self._cs is None:
            log.warning("Capstone not available for gadget finding")
            return {}

        gadgets = {}

        # Scan executable sections
        for obj in self.project.loader.all_objects:
            for section in obj.sections:
                if not section.is_executable:
                    continue

                try:
                    data = self.project.loader.memory.load(
                        section.vaddr, section.memsize
                    )
                except Exception:
                    continue

                # Find gadgets ending in ret
                gadgets.update(self._find_ret_gadgets(
                    self._cs, data, section.vaddr
                ))

        self.gadgets = gadgets
        log.info(f"Found {len(gadgets)} potential ROP gadgets")
        return gadgets

    def _find_ret_gadgets(self, cs, data: bytes, base_addr: int) -> dict[int, RopGadget]:
        """Find gadgets ending in ret instruction."""
        gadgets = {}

        # Find all ret instructions
        ret_offsets = []
        for i, b in enumerate(data):
            # x86/x64: ret = 0xc3, ret imm16 = 0xc2
            if b == 0xc3 or b == 0xc2:
                ret_offsets.append(i)

        # For each ret, try to find valid gadgets leading to it
        for ret_off in ret_offsets:
            ret_addr = base_addr + ret_off

            # Try different starting points (up to max_gadget_length instructions back)
            for start in range(max(0, ret_off - 20), ret_off):
                try:
                    gadget_bytes = data[start:ret_off + 1]
                    instructions = list(cs.disasm(gadget_bytes, base_addr + start))

                    # Check if this disassembles cleanly to a ret
                    if not instructions:
                        continue

                    # Check if last instruction is ret
                    last = instructions[-1]
                    if last.mnemonic not in ('ret', 'retn'):
                        continue

                    # Check length
                    if len(instructions) > self.max_gadget_length:
                        continue

                    # Valid gadget found
                    gadget_addr = base_addr + start
                    gadget = RopGadget(
                        addr=gadget_addr,
                        instructions=[f"{i.mnemonic} {i.op_str}".strip()
                                     for i in instructions],
                        gadget_type='ret',
                        length=len(instructions),
                    )
                    gadgets[gadget_addr] = gadget

                except Exception:
                    continue

        return gadgets

    def analyze_state(self, state: "angr.SimState",
                      return_history: list[tuple[int, int]]) -> RopChain | None:
        """
        Analyze execution state for ROP patterns.

        Args:
            state: Current symbolic state
            return_history: List of (return_addr, target) tuples

        Returns:
            RopChain if detected, None otherwise
        """
        if len(return_history) < self.min_chain_length:
            return None

        # Check for consecutive returns to gadget-like addresses
        potential_chain = []
        consecutive_gadgets = 0

        for ret_addr, target in return_history[-20:]:  # Check recent history
            # Is this a known gadget?
            if target in self.gadgets:
                gadget = self.gadgets[target]
                potential_chain.append(gadget)
                consecutive_gadgets += 1
            else:
                # Check if it looks like a gadget (short sequence)
                if self._looks_like_gadget(target):
                    consecutive_gadgets += 1
                else:
                    # Chain broken
                    if consecutive_gadgets >= self.min_chain_length:
                        break
                    consecutive_gadgets = 0
                    potential_chain.clear()

        if len(potential_chain) >= self.min_chain_length:
            chain = RopChain(
                gadgets=potential_chain,
                start_addr=potential_chain[0].addr if potential_chain else 0,
                detected_at_step=state.history.depth if state.history else 0,
                confidence=min(1.0, len(potential_chain) / 10.0),
            )
            self.detected_chains.append(chain)
            log.warning(f"ROP chain detected! {len(potential_chain)} gadgets, "
                       f"confidence: {chain.confidence:.2f}")
            return chain

        return None

    def _looks_like_gadget(self, addr: int) -> bool:
        """Check if an address looks like it could be a gadget."""
        if self._cs is None:
            return False

        try:
            # Read a few bytes and disassemble
            data = self.project.loader.memory.load(addr, 20)

            instructions = list(self._cs.disasm(data, addr))
            if not instructions:
                return False

            # Check if there's a ret within max_gadget_length
            for i, insn in enumerate(instructions[:self.max_gadget_length]):
                if insn.mnemonic in ('ret', 'retn'):
                    return True

        except Exception:
            pass

        return False

    def get_detected_chains(self) -> list[RopChain]:
        """Get all detected ROP chains."""
        return self.detected_chains.copy()

    def reset(self):
        """Reset detection state."""
        self.detected_chains.clear()


class JopDetector:
    """
    Detects Jump-Oriented Programming patterns.

    JOP detection is based on:
    1. Identifying dispatcher gadgets (jmp [reg] or jmp reg patterns)
    2. Tracking indirect jumps during execution
    3. Detecting jump table patterns
    4. Correlating with dynamically mapped memory
    """

    def __init__(self, project: "angr.Project",
                 memory_tracker: "MemoryRegionTracker | None" = None):
        self.project = project
        self.memory_tracker = memory_tracker

        # Pre-discovered gadgets
        self.dispatchers: dict[int, JopGadget] = {}
        self.functional_gadgets: dict[int, JopGadget] = {}

        # Detection results
        self.detected_chains: list[JopChain] = []

        # Configuration
        self.max_gadget_length = 10

        # Cached Capstone disassembler instance
        self._cs = self._create_capstone()

    def _create_capstone(self):
        """Create a Capstone disassembler for the project architecture."""
        try:
            import capstone
        except ImportError:
            return None
        arch_name = self.project.arch.name
        if arch_name in ('AMD64', 'X86_64', 'X86'):
            mode = capstone.CS_MODE_64 if self.project.arch.bits == 64 else capstone.CS_MODE_32
            cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        elif arch_name == 'AARCH64':
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif arch_name in ('ARM', 'ARMEL', 'ARMHF'):
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            return None
        cs.detail = True
        return cs

    def find_gadgets(self) -> tuple[dict[int, JopGadget], dict[int, JopGadget]]:
        """
        Pre-analyze binary to find JOP gadgets.

        Returns (dispatchers, functional_gadgets).
        """
        if self._cs is None:
            log.warning("Capstone not available for JOP gadget finding")
            return {}, {}

        dispatchers = {}
        functional = {}

        # Scan executable sections
        for obj in self.project.loader.all_objects:
            for section in obj.sections:
                if not section.is_executable:
                    continue

                try:
                    data = self.project.loader.memory.load(
                        section.vaddr, section.memsize
                    )
                except Exception:
                    continue

                d, f = self._find_jop_gadgets(self._cs, data, section.vaddr)
                dispatchers.update(d)
                functional.update(f)

        self.dispatchers = dispatchers
        self.functional_gadgets = functional
        log.info(f"Found {len(dispatchers)} JOP dispatchers, "
                f"{len(functional)} functional gadgets")
        return dispatchers, functional

    def _find_jop_gadgets(self, cs, data: bytes, base_addr: int) -> tuple[dict, dict]:
        """Find JOP dispatcher and functional gadgets."""
        dispatchers = {}
        functional = {}

        # Look for jmp reg, jmp [reg], call reg patterns
        jmp_patterns = [
            b'\xff\xe0',  # jmp rax
            b'\xff\xe1',  # jmp rcx
            b'\xff\xe2',  # jmp rdx
            b'\xff\xe3',  # jmp rbx
            b'\xff\xe4',  # jmp rsp
            b'\xff\xe6',  # jmp rsi
            b'\xff\xe7',  # jmp rdi
        ]

        for i in range(len(data) - 1):
            for pattern in jmp_patterns:
                if data[i:i+len(pattern)] == pattern:
                    addr = base_addr + i

                    # Try to disassemble backwards to find full gadget
                    gadget = self._extract_jop_gadget(cs, data, i, base_addr)
                    if gadget:
                        dispatchers[addr] = gadget

        return dispatchers, functional

    def _extract_jop_gadget(self, cs, data: bytes, jmp_offset: int,
                           base_addr: int) -> JopGadget | None:
        """Extract a JOP gadget ending at the given jump instruction."""
        # Try different starting points
        for start in range(max(0, jmp_offset - 20), jmp_offset):
            try:
                gadget_bytes = data[start:jmp_offset + 2]
                instructions = list(cs.disasm(gadget_bytes, base_addr + start))

                if not instructions:
                    continue

                # Check if last instruction is indirect jmp/call
                last = instructions[-1]
                if last.mnemonic not in ('jmp', 'call'):
                    continue

                # Check if it's indirect
                if not any(c in last.op_str for c in ['r', '[']):
                    continue

                if len(instructions) <= self.max_gadget_length:
                    return JopGadget(
                        addr=base_addr + start,
                        instructions=[f"{i.mnemonic} {i.op_str}".strip()
                                     for i in instructions],
                        gadget_type='dispatcher',
                        target_reg=self._extract_target_reg(last.op_str),
                    )

            except Exception:
                continue

        return None

    def _extract_target_reg(self, op_str: str) -> str | None:
        """Extract target register from operand string."""
        regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        for reg in regs:
            if reg in op_str.lower():
                return reg
        return None

    def analyze_state(self, state: "angr.SimState",
                      flow_tracker: IndirectFlowTracker) -> JopChain | None:
        """
        Analyze execution state for JOP patterns.

        Args:
            state: Current symbolic state
            flow_tracker: IndirectFlowTracker with jump history

        Returns:
            JopChain if detected, None otherwise
        """
        events = flow_tracker.get_all_events()
        indirect_jumps = [e for e in events if e.event_type == 'jump']

        if len(indirect_jumps) < 3:
            return None

        # Look for dispatcher pattern - same instruction being hit repeatedly
        jump_targets = [e.target_addr for e in indirect_jumps[-20:]]
        target_counts = {}
        for t in jump_targets:
            target_counts[t] = target_counts.get(t, 0) + 1

        # If any target appears multiple times, could be a dispatcher
        potential_dispatchers = [t for t, c in target_counts.items() if c >= 2]

        if potential_dispatchers:
            dispatcher = None
            if potential_dispatchers[0] in self.dispatchers:
                dispatcher = self.dispatchers[potential_dispatchers[0]]

            chain = JopChain(
                dispatcher=dispatcher,
                gadgets=[],  # Would need more analysis
                detected_at_step=state.history.depth if state.history else 0,
                confidence=0.5,
            )
            self.detected_chains.append(chain)
            log.warning(f"Potential JOP dispatcher detected at "
                       f"0x{potential_dispatchers[0]:x}")
            return chain

        return None

    def get_detected_chains(self) -> list[JopChain]:
        """Get all detected JOP chains."""
        return self.detected_chains.copy()

    def reset(self):
        """Reset detection state."""
        self.detected_chains.clear()
