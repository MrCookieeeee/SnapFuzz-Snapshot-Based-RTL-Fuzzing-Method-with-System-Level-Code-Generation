from pathlib import Path
import os


def _get_root_path() -> Path:
    root = os.getenv("SNAPFUZZ_DIR")
    if not root:
        raise RuntimeError("SNAPFUZZ_DIR is not set")
    return Path(root)


def get_root_path() -> Path:
    return _get_root_path()


# ---------------------------------------------------------------------------
# run_time_data
# ---------------------------------------------------------------------------

def get_runtime_data_dir() -> Path:
    return _get_root_path() / "run_time_data"


def get_line_cov_soc_path(design_name: str) -> Path:
    return get_runtime_data_dir() / f"{design_name}_line_cov.dat"


def get_single_elf_line_cov_path(design_name: str, elf_name: str) -> Path:
    return get_runtime_data_dir() / f"{design_name}_{elf_name}_line_cov.dat"

def get_merged_line_cov_path(design_name: str) -> Path:
    return get_runtime_data_dir() / f"{design_name}_line_cov_merged.dat"

def get_merged_line_cov_lock(design_name: str) -> Path:
    return get_runtime_data_dir() / f"{design_name}_line_cov_merged.lock"

def get_merged_line_cov_tmp(design_name: str) -> Path:
    return get_runtime_data_dir() / f"{design_name}_line_cov_merged.tmp"

def get_cov_txt_path(cov_file: str) -> Path:
    return get_runtime_data_dir() / f"{cov_file}.txt"

def get_merged_br_cov_path(design_name: str) -> Path:
    return get_runtime_data_dir() / f"{design_name}_br_cov_merged.dat"

# ---------------------------------------------------------------------------
# Coverage analysis / RTL slices
# ---------------------------------------------------------------------------

def get_slice_dir_path(design_name: str, checkpoint_instr_count: int) -> Path:
    return get_runtime_data_dir() / f"{design_name}_{checkpoint_instr_count}instr_slice"

def get_rtl_slice_sv_path(design_name: str, checkpoint_instr_count: int) -> Path:
    return get_slice_dir_path(design_name, checkpoint_instr_count) / "vanilla.sv"

def get_rtl_slice_json_path(design_name: str, checkpoint_instr_count: int) -> Path:
    return get_slice_dir_path(design_name, checkpoint_instr_count) / "module_mapping.json"

def get_save_checkpoint_json_path(design_name: str, checkpoint_instr_count: int) -> Path:
    return get_slice_dir_path(design_name, checkpoint_instr_count) / "checkpoint.json"

# ---------------------------------------------------------------------------
# Simulator executables
# ---------------------------------------------------------------------------

def get_soc_dir() -> Path:
    return _get_root_path() / "soc"


def get_sim_executable_path(design_name: str) -> Path:
    return get_soc_dir() / f"V{design_name}_br_soc"


def get_line_cov_sim_path(design_name: str) -> Path:
    return get_soc_dir() / f"V{design_name}_line_soc"


def get_bench_dir() -> Path:
    return _get_root_path() / "bench"


def get_bench_sim_path(design_name: str) -> Path:
    return get_bench_dir() / "br_cov" / f"V{design_name}_tiny_soc"


def get_xiangshan_emu_path() -> Path:
    return get_soc_dir() / "emuDefaultConfig8Threads"


def get_xiangshan_nemu_path() -> Path:
    return get_soc_dir() / "nemu"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def get_design_cfg_path(design_name: str) -> Path:
    return _get_root_path() / "src" / "common" / "cfgs" / f"{design_name}.json"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def get_log_dir() -> Path:
    return _get_root_path() / "log"


def get_cov_log_path_snapfuzz(design_name: str, tag: str) -> Path:
    return get_log_dir() / f"{design_name}_cov_log_{tag}_snapfuzz.json"


# ---------------------------------------------------------------------------
# Root-level merged coverage snapshot
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# ELF directories
# ---------------------------------------------------------------------------

def get_data_dir() -> Path:
    return _get_root_path() / "data"


def get_riscv_dv_elfs_dir() -> Path:
    return _get_root_path() / "riscv_dv" / "riscv_dv_elfs"


def get_riscv_dv_xiangshan_elfs_dir() -> Path:
    return _get_root_path() / "riscv_dv" / "riscv_dv_elfs_xiangshan"


def get_warmup_elf_path() -> Path:
    return _get_root_path() / "src" / "warmup_elfs" / "warmup.elf"


# ---------------------------------------------------------------------------
# Benchmark / instruction distribution
# ---------------------------------------------------------------------------

def get_benchmark_instr_dist_dir() -> Path:
    return _get_root_path() / "benchmark" / "instr_distribution"


def get_profiling_elf_path(design_name: str) -> Path:
    return get_data_dir() / f"medelegprofiling{design_name}.elf"