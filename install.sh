#!/bin/bash
# DynPathResolver Installation Script
# Supports: Ubuntu/Debian, Fedora/RHEL, macOS

set -e

echo "=========================================="
echo "  DynPathResolver Installation Script"
echo "=========================================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -f /etc/debian_version ]; then
        OS="debian"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
    else
        OS="linux"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "[*] Detected OS: $OS"

# Install system dependencies
install_deps() {
    echo "[*] Installing system dependencies..."

    case $OS in
        debian)
            sudo apt-get update
            sudo apt-get install -y \
                python3 \
                python3-venv \
                python3-dev \
                python3-pip \
                gcc \
                g++ \
                make \
                git \
                libffi-dev \
                libssl-dev
            ;;
        redhat)
            sudo dnf install -y \
                python3 \
                python3-devel \
                python3-pip \
                gcc \
                gcc-c++ \
                make \
                git \
                libffi-devel \
                openssl-devel
            ;;
        macos)
            # Check for Homebrew
            if ! command -v brew &> /dev/null; then
                echo "[!] Homebrew not found. Please install it first:"
                echo '    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                exit 1
            fi
            brew install python@3.11 || true
            ;;
    esac
}

# Create virtual environment
setup_venv() {
    echo "[*] Setting up Python virtual environment..."

    VENV_DIR=".venv"

    if [ -d "$VENV_DIR" ]; then
        echo "[*] Virtual environment already exists, skipping creation"
    else
        python3 -m venv "$VENV_DIR"
    fi

    # Activate venv
    source "$VENV_DIR/bin/activate"

    # Upgrade pip
    pip install --upgrade pip
}

# Install Python dependencies
install_python_deps() {
    echo "[*] Installing Python dependencies..."

    # Install package in editable mode with dev dependencies
    pip install -e ".[dev]"

    echo "[*] Verifying installation..."
    python -c "from dynpathresolver import DynPathResolver; print('DynPathResolver imported successfully')"
    python -c "import angr; print(f'angr version: {angr.__version__}')"
}

# Build example binaries (Linux only)
build_examples() {
    if [[ "$OS" != "macos" ]]; then
        echo "[*] Building example binaries..."

        if [ -d "examples/complex_loader" ]; then
            cd examples/complex_loader
            make clean
            make all
            cd ../..
            echo "[*] Example binaries built successfully"
        fi
    else
        echo "[*] Skipping example build on macOS (use Docker for Linux binaries)"
    fi
}

# Run tests
run_tests() {
    echo "[*] Running tests..."
    pytest -v --tb=short
}

# Main installation
main() {
    # Check if we're in the right directory
    if [ ! -f "pyproject.toml" ]; then
        echo "[!] Error: pyproject.toml not found"
        echo "    Please run this script from the DynPathResolver root directory"
        exit 1
    fi

    # Parse arguments
    SKIP_DEPS=false
    SKIP_TESTS=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --help)
                echo "Usage: ./install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-deps    Skip system dependency installation"
                echo "  --skip-tests   Skip running tests after installation"
                echo "  --help         Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Run installation steps
    if [ "$SKIP_DEPS" = false ]; then
        install_deps
    fi

    setup_venv
    install_python_deps
    build_examples

    if [ "$SKIP_TESTS" = false ]; then
        run_tests
    fi

    echo ""
    echo "=========================================="
    echo "  Installation Complete!"
    echo "=========================================="
    echo ""
    echo "To activate the virtual environment:"
    echo "    source .venv/bin/activate"
    echo ""
    echo "To run an analysis:"
    echo "    python examples/run_analysis.py examples/complex_loader/loader"
    echo ""
    echo "To run tests:"
    echo "    pytest -v"
    echo ""
}

main "$@"
