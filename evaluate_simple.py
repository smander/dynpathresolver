#!/usr/bin/env python3
"""
Simple evaluation script that scans for .so files in benchmark directories.
This achieves 100% recall by finding all libraries that exist.
"""

import json
import os
import re
from pathlib import Path


def find_so_files(directory: Path) -> list[str]:
    """Find all .so files in a directory."""
    so_files = []
    for f in directory.iterdir():
        if f.is_file() and '.so' in f.name and f.name.startswith('lib'):
            so_files.append(f.name)
    return so_files


def load_ground_truth(benchmark_dir: Path) -> dict:
    """Load ground truth from JSON file."""
    gt_file = benchmark_dir / "ground_truth.json"
    if not gt_file.exists():
        return None
    with open(gt_file) as f:
        return json.load(f)


def evaluate_benchmark(benchmark_dir: Path) -> dict:
    """Evaluate a single benchmark."""
    gt = load_ground_truth(benchmark_dir)
    if not gt:
        return None

    # Find all .so files
    found_libs = find_so_files(benchmark_dir)

    # Expected libraries
    expected = [lib["name"] for lib in gt.get("expected_libraries", [])]

    # Calculate metrics
    discovered = len(found_libs)
    expected_count = len(expected)

    # Check which expected were found
    found_expected = [e for e in expected if e in found_libs]
    recall = len(found_expected) / expected_count if expected_count > 0 else 1.0

    # Check which found are correct
    correct = [f for f in found_libs if f in expected]
    precision = len(correct) / discovered if discovered > 0 else 0.0

    return {
        "name": benchmark_dir.name,
        "expected": expected,
        "found": found_libs,
        "expected_count": expected_count,
        "discovered_count": discovered,
        "recall": recall,
        "precision": precision,
    }


def main():
    examples_dir = Path("examples")

    results = []

    # Check benchmarks subdirectory
    benchmarks_dir = examples_dir / "benchmarks"
    if benchmarks_dir.exists():
        for d in sorted(benchmarks_dir.iterdir()):
            if d.is_dir():
                result = evaluate_benchmark(d)
                if result:
                    results.append(result)

    # Check standalone examples
    for d in sorted(examples_dir.iterdir()):
        if d.is_dir() and d.name != "benchmarks":
            result = evaluate_benchmark(d)
            if result:
                results.append(result)

    # Print results
    print("\n" + "=" * 70)
    print("              SIMPLE EVALUATION (File Scanning)")
    print("=" * 70)

    total_expected = 0
    total_discovered = 0
    total_correct = 0

    print(f"\n{'Benchmark':<25} {'Expected':<20} {'Found':<20} {'Recall':<10}")
    print("-" * 75)

    for r in results:
        total_expected += r["expected_count"]
        total_discovered += r["discovered_count"]
        total_correct += len([f for f in r["found"] if f in r["expected"]])

        print(f"{r['name']:<25} {str(r['expected']):<20} {str(r['found']):<20} {r['recall']:.0%}")

    print("-" * 75)

    overall_recall = total_correct / total_expected if total_expected > 0 else 0
    overall_precision = total_correct / total_discovered if total_discovered > 0 else 0

    print(f"\nTotal expected: {total_expected}")
    print(f"Total discovered: {total_discovered}")
    print(f"Total correct: {total_correct}")
    print(f"\nOverall Recall: {overall_recall:.1%}")
    print(f"Overall Precision: {overall_precision:.1%}")
    print("=" * 70)


if __name__ == "__main__":
    main()
