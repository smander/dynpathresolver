#!/bin/bash
#
# DynPathResolver Benchmark Runner
#
# Runs each of the 16 benchmarks individually inside the Docker container,
# evaluating library discovery recall against ground truth.
#
# Usage:
#   ./run_benchmarks.sh              # Run all 16 benchmarks
#   ./run_benchmarks.sh 05           # Run only benchmarks matching "05"
#   ./run_benchmarks.sh 05 08 16     # Run specific benchmarks
#   ./run_benchmarks.sh --verbose    # Show detailed output per benchmark
#

set -euo pipefail

CONTAINER="dynpathresolver"
MAX_STEPS=200
VERBOSE=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# All benchmarks in order
ALL_BENCHMARKS=(
    01_simple_dlopen
    02_environment_path
    03_xor_encrypted
    04_computed_path
    05_multi_stage
    06_stack_strings
    07_time_triggered
    08_anti_debug
    09_memfd_create
    10_indirect_call
    11_multi_encoding
    12_manual_elf_load
    13_mmap_exec
    14_rop_chain
    16_signal_handler
    17_network_socket
)

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
SELECTED=()
for arg in "$@"; do
    if [[ "$arg" == "--verbose" || "$arg" == "-v" ]]; then
        VERBOSE=1
    elif [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
        echo "Usage: $0 [--verbose] [BENCHMARK_FILTER ...]"
        echo ""
        echo "  Run with no args to test all 16 benchmarks."
        echo "  Pass one or more filters to match benchmark names (e.g. 05, anti, signal)."
        echo ""
        echo "Options:"
        echo "  --verbose, -v   Show detailed per-benchmark output"
        echo "  --help, -h      Show this help"
        exit 0
    else
        # Match filter against benchmark names
        for bm in "${ALL_BENCHMARKS[@]}"; do
            if [[ "$bm" == *"$arg"* ]]; then
                SELECTED+=("$bm")
            fi
        done
    fi
done

# Default to all benchmarks if no filter given
if [[ ${#SELECTED[@]} -eq 0 && $VERBOSE -eq 0 ]] || [[ ${#SELECTED[@]} -eq 0 ]]; then
    for arg in "$@"; do
        if [[ "$arg" != "--verbose" && "$arg" != "-v" ]]; then
            # A filter was given but matched nothing
            echo -e "${RED}No benchmarks matched filter: $arg${NC}"
            exit 1
        fi
    done
    SELECTED=("${ALL_BENCHMARKS[@]}")
fi

# ---------------------------------------------------------------------------
# Check Docker container
# ---------------------------------------------------------------------------
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo -e "${RED}Error: Docker container '${CONTAINER}' is not running.${NC}"
    echo "Start it with: docker compose up -d"
    exit 1
fi

# ---------------------------------------------------------------------------
# Run benchmarks
# ---------------------------------------------------------------------------
echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD}     DynPathResolver Individual Benchmark Evaluation${NC}"
echo -e "${BOLD}================================================================${NC}"
echo -e "Container:  ${CYAN}${CONTAINER}${NC}"
echo -e "Max steps:  ${MAX_STEPS}"
echo -e "Benchmarks: ${#SELECTED[@]}"
echo ""

PASSED=0
FAILED=0
SKIPPED=0
ERRORS=0
RESULTS=()

for BENCHMARK in "${SELECTED[@]}"; do
    printf "  %-25s" "$BENCHMARK"

    OUTPUT=$(docker exec "$CONTAINER" python3 -c "
import sys, json, os, gc, re, time
from pathlib import Path
import logging
logging.disable(logging.CRITICAL)

sys.path.insert(0, '/app')

import angr
from dynpathresolver import DynPathResolver, DynDlopen, DynDlsym

benchmark_dir = Path('/app/examples/benchmarks/${BENCHMARK}')
binary_path = benchmark_dir / 'test_binary'

# --- Validate files exist ---
if not binary_path.exists():
    print('SKIP|0|0|0.0|no test_binary')
    sys.exit(0)

gt_file = benchmark_dir / 'ground_truth.json'
if not gt_file.exists():
    print('SKIP|0|0|0.0|no ground_truth.json')
    sys.exit(0)

with open(gt_file) as f:
    gt = json.load(f)
expected = [lib['name'] for lib in gt.get('expected_libraries', [])]

# --- Reset state ---
DynDlopen.reset()
DynDlsym.reset()

try:
    project = angr.Project(str(binary_path), auto_load_libs=False)

    # --- Run DynPathResolver ---
    extra_kwargs = {}
    if '${BENCHMARK}' == '17_network_socket':
        extra_kwargs = dict(
            track_network=True,
            network_payloads={200: b'./libnetplugin.so'},
        )

    dpr = DynPathResolver(
        library_paths=[str(benchmark_dir)],
        preload_common=False,
        handle_syscall_loading=True,
        track_signals=True,
        track_security_policy=True,
        **extra_kwargs,
    )

    state = project.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )
    simgr = project.factory.simgr(state)
    simgr.use_technique(dpr)

    start = time.time()
    step = 0
    try:
        while len(simgr.active) > 0 and step < ${MAX_STEPS}:
            simgr.step()
            step += 1
            if len(simgr.active) > 32:
                simgr.active = simgr.active[:32]
    except:
        pass
    elapsed = time.time() - start

    try:
        dpr.complete(simgr)
    except:
        pass

    # --- Collect results ---
    discovered = set()
    for handle, lib_info in DynDlopen.loaded_libraries.items():
        if hasattr(lib_info, 'binary'):
            discovered.add(os.path.basename(lib_info.binary))
        elif isinstance(lib_info, dict):
            discovered.add(os.path.basename(lib_info.get('path', '')))

    found_expected = [e for e in expected if e in discovered]
    recall = len(found_expected) / len(expected) if expected else 1.0

    status = 'PASS' if recall >= 1.0 else 'FAIL'

    # Collect library load events info
    events = dpr.get_library_load_events()
    event_details = []
    for ev in events:
        detail = ev.library_name
        if ev.register_snapshot:
            detail += f' regs={len(ev.register_snapshot.registers)}'
        if ev.call_stack:
            detail += f' stack={len(ev.call_stack)}'
        event_details.append(detail)

    # Output: STATUS|step|recall|elapsed|expected|discovered|events
    parts = [
        status,
        str(step),
        f'{recall:.0%}',
        f'{elapsed:.1f}',
        ','.join(expected),
        ','.join(sorted(discovered)) if discovered else '-',
        ';'.join(event_details) if event_details else '-',
    ]
    print('|'.join(parts))

    del simgr, state, project, dpr
    gc.collect()

except Exception as e:
    print(f'ERROR|0|0%|0.0|{e}')
" 2>&1)

    # Parse output (last line is the result)
    RESULT_LINE=$(echo "$OUTPUT" | tail -1)
    IFS='|' read -r STATUS STEPS RECALL ELAPSED REST <<< "$RESULT_LINE"

    case "$STATUS" in
        PASS)
            echo -e "${GREEN}PASS${NC}  recall=${RECALL}  steps=${STEPS}  time=${ELAPSED}s"
            ((PASSED++))
            ;;
        FAIL)
            echo -e "${RED}FAIL${NC}  recall=${RECALL}  steps=${STEPS}  time=${ELAPSED}s"
            ((FAILED++))
            ;;
        SKIP)
            echo -e "${YELLOW}SKIP${NC}  ${REST}"
            ((SKIPPED++))
            ;;
        ERROR)
            echo -e "${RED}ERROR${NC} ${REST}"
            ((ERRORS++))
            ;;
        *)
            echo -e "${RED}ERROR${NC} unexpected output"
            ((ERRORS++))
            ;;
    esac

    RESULTS+=("$RESULT_LINE")

    # Verbose: show details
    if [[ $VERBOSE -eq 1 && "$STATUS" != "SKIP" ]]; then
        IFS='|' read -r _ _ _ _ EXPECTED DISCOVERED EVENTS <<< "$RESULT_LINE"
        echo -e "                              expected:   ${EXPECTED}"
        echo -e "                              discovered: ${DISCOVERED}"
        if [[ "$EVENTS" != "-" ]]; then
            echo -e "                              events:     ${EVENTS}"
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD}  SUMMARY${NC}"
echo -e "${BOLD}================================================================${NC}"

TOTAL=$((PASSED + FAILED + SKIPPED + ERRORS))

echo -e "  ${GREEN}PASS:${NC}    ${PASSED}/${TOTAL}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "  ${RED}FAIL:${NC}    ${FAILED}/${TOTAL}"
fi
if [[ $SKIPPED -gt 0 ]]; then
    echo -e "  ${YELLOW}SKIP:${NC}    ${SKIPPED}/${TOTAL}"
fi
if [[ $ERRORS -gt 0 ]]; then
    echo -e "  ${RED}ERROR:${NC}   ${ERRORS}/${TOTAL}"
fi
echo -e "${BOLD}================================================================${NC}"

# Exit with failure if any benchmark failed
if [[ $FAILED -gt 0 || $ERRORS -gt 0 ]]; then
    exit 1
fi
