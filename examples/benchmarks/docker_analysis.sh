#!/bin/bash
# Run DynPathResolver analysis on benchmarks from within Docker
# This ensures proper analysis of ARM64 binaries in a compatible environment

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    DOCKER_PLATFORM="linux/arm64"
else
    DOCKER_PLATFORM="linux/amd64"
fi

echo "=== DynPathResolver Docker Analysis ==="
echo "Architecture: $ARCH"
echo "Docker platform: $DOCKER_PLATFORM"
echo ""

# Create a Dockerfile for analysis
cat > "$SCRIPT_DIR/Dockerfile.analysis" << 'DOCKERFILE'
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir angr

# Set working directory
WORKDIR /app

# Copy project
COPY . /app/

# Install dynpathresolver
RUN pip install -e .

# Default command
CMD ["python", "examples/benchmarks/run_analysis.py"]
DOCKERFILE

echo "=== Building analysis Docker image ==="
docker build -t dynpathresolver-analysis \
    --platform "$DOCKER_PLATFORM" \
    -f "$SCRIPT_DIR/Dockerfile.analysis" \
    "$PROJECT_ROOT"

echo ""
echo "=== Running analysis in Docker ==="
docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$PROJECT_ROOT:/app" \
    -w /app \
    dynpathresolver-analysis \
    python examples/benchmarks/run_analysis.py

echo ""
echo "=== Analysis Complete ==="
echo "Results saved to: examples/benchmarks/analysis_results.json"
