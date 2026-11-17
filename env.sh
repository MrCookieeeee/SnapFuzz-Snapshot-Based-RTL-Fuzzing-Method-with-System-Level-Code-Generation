myroot="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SNAPFUZZ_DIR="$myroot"
export SNAPFUZZ_RISCV_BITWIDTH=64

# Riscv Tools
export PATH="set your own path":$PATH

# verilator 5.006
export PATH="set your own path:$PATH"

echo "SnapFuzz root: $SNAPFUZZ_DIR"
export PYTHONPATH="$SNAPFUZZ_DIR:$SNAPFUZZ_DIR/src:$PYTHONPATH"
