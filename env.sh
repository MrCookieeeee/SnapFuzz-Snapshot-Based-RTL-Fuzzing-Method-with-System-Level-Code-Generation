myroot="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SNAPFUZZ_DIR="$myroot"
export SNAPFUZZ_RISCV_BITWIDTH=64

# Riscv Tools
export PATH="$SNAPFUZZ_DIR/riscv/bin":$PATH

# verilator 5.006
export PATH="${SNAPFUZZ_VERILATOR_BIN:-$HOME/Tools/verilator-5.006/install/bin}:$PATH"

echo "SnapFuzz root: $SNAPFUZZ_DIR"
export PYTHONPATH="$SNAPFUZZ_DIR:$SNAPFUZZ_DIR/src:$PYTHONPATH"
