# DynPathResolver Docker Image
# Based on Ubuntu 22.04 with Python 3.11 and angr

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    gcc \
    g++ \
    make \
    git \
    wget \
    curl \
    gdb \
    file \
    binutils \
    libc6-dev \
    ltrace \
    texlive-latex-base \
    texlive-latex-recommended \
    texlive-latex-extra \
    texlive-fonts-recommended \
    texlive-science \
    texlive-bibtex-extra \
    texlive-publishers \
    biber \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.11 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1

# Create working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Create virtual environment and install dependencies
RUN python3 -m venv /app/.venv \
    && /app/.venv/bin/pip install --upgrade pip \
    && /app/.venv/bin/pip install -e ".[dev]" \
    && /app/.venv/bin/pip install frida-tools frida

# Build example binaries
RUN cd /app/examples/complex_loader && make clean && make all
RUN cd /app/examples/network_triggered_loader && make clean && make all

# Build benchmark suite (all 12 benchmarks)
RUN for dir in /app/examples/benchmarks/*/; do \
        if [ -f "$dir/Makefile" ]; then \
            cd "$dir" && make clean && make all || true; \
        fi; \
    done

# Set environment
ENV PATH="/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

# Default command: run tests
CMD ["pytest", "-v"]
