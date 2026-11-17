import time
import random
import threading
import os
import json as _json
import multiprocessing as mp
import subprocess
import traceback
from makeelf.elf import *

from initialstate.FuzzerState import FuzzerState
from coverage.CovState import CovState
from coverage.CovAnalysis import compute_category_ratios
from coverage.CoverageYieldRebalancer import CYWRRebalancer
from functools import partial

from generation.GenBasicBlocks import gen_basicblocks
from generation.SpikeResolution import spike_resolution
from generation.GenElf import gen_elf_from_bbs
from common.Spike import calibrate_spikespeed, SPIKE_MEDELEG_MASK
from common.ProfileDesign import profile_get_medeleg_mask
from common.GetCfgs import get_design_boot_addr
from common.path import (get_merged_br_cov_path, get_merged_line_cov_path, get_cov_log_path_snapfuzz,
                         get_riscv_dv_elfs_dir, get_warmup_elf_path,
                         get_xiangshan_emu_path, get_xiangshan_nemu_path)
from run_verilator import runtest_verilator_br_cov, runtest_verilator_line_cov, runtest_verilator_br_cov_elfs
from generation.Instructions import ISAInstClass_Initial_Boosters
from params.fuzzparams import MAX_BASIC_BLOCK_COUNT
from params.runparams  import NO_REMOVE_TMPFILES

# max mem size: 4MB
LOG2_MEMSIZE_UPPERBOUND = 20
PRINT_COV_TIME          = 60

# for cov data handling
merged_cov_datas     = []
line_cov_data        = ""

# for thread 
callback_lock  = threading.Lock()
newly_finished_tests = 0

# elf_list_num
elf_list_num = 0

# for summary
all_done_tests = 0
all_done_instructions = 0

# for time control
start_time = time.time()

# elf list config
enable_elf_lists          = False

new_test_event = threading.Event()

# Coverage-over-time logging
_cov_log_records = []  # list of dicts for JSON export

global_instr_prob = dict(ISAInstClass_Initial_Boosters)

def _log_coverage_snapshot(cov_state, elapsed_secs, iteration):
    """Append a coverage snapshot to the in-memory log."""
    br_ones = br_total = cond_ones = cond_total = 0
    for v in cov_state.merged_cov['br_cov'].values():
        br_ones  += v.count('1')
        br_total += len(v)
    for v in cov_state.merged_cov['cond_cov'].values():
        cond_ones  += v.count('1')
        cond_total += len(v)

    line_cov_ratio = 0.0
    try:
        inside = cov_state.line_cov.split(")")[0].strip("(")
        num, den = map(int, inside.split("/"))
        line_cov_ratio = num / den if den else 0.0
    except Exception:
        pass

    record = {
        "elapsed_s":   round(elapsed_secs, 2),
        "iteration":   iteration,
        "br_covered":  br_ones,
        "br_total":    br_total,
        "br_ratio":    round(br_ones / br_total, 6) if br_total else 0.0,
        "cond_covered": cond_ones,
        "cond_total":   cond_total,
        "cond_ratio":   round(cond_ones / cond_total, 6) if cond_total else 0.0,
        "line_ratio":   round(line_cov_ratio, 6),
    }
    _cov_log_records.append(record)


def _flush_cov_log(design_name, no_update=False):
    """Write the coverage log to a JSON file."""
    tag = "upgrade_off" if no_update else "upgrade_on"
    log_path = get_cov_log_path_snapfuzz(design_name, tag)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as f:
        _json.dump(_cov_log_records, f, indent=2)
    print(f"Coverage log written to {log_path}")


def _do_coverage_merge(cov_state: 'CovState', design_name, start_time):
    """
    Core coverage merge / compute / log cycle.

    Reusable helper called by the time-interval trigger.
    
    **Must be called under callback_lock.**
    """
    cov_state.merge_coverage_data(merged_cov_datas, line_cov_data)

    merge_data_path = get_merged_br_cov_path(design_name)
    with open(merge_data_path, "w") as f:
        f.write(str(cov_state.merged_cov))

    cov_state.compute_coverage(start_time)
    _log_coverage_snapshot(cov_state, time.time() - start_time, all_done_tests)
    merged_cov_datas.clear()
    print(f"all done tests: {all_done_tests}")
    print(f"accepted body instructions: {all_done_instructions}")

# Creates a new program descriptor.
def gen_new_test_instance(design_name: str, randseed: int, can_authorize_privileges: bool, fixed_memsize: int = None, fixed_num_bbs: int = None):
    mem_size = random.randrange(1 << 14, 1 << LOG2_MEMSIZE_UPPERBOUND) if fixed_memsize is None else fixed_memsize
    num_bbs  = random.randrange(20, MAX_BASIC_BLOCK_COUNT) if fixed_num_bbs is None else fixed_num_bbs
    return mem_size, design_name, randseed, num_bbs, can_authorize_privileges

def test_done_callback(arg):
    """
    treat branch and cond coverage
    """
    global newly_finished_tests, callback_lock, merged_cov_datas, line_cov_data, all_done_tests
    global all_done_instructions
    with callback_lock:
        merged_cov_datas.append(arg[0]) 
        line_cov_data = arg[1]
        newly_finished_tests += 1
        all_done_tests += 1
        if len(arg) > 2:
            all_done_instructions += arg[2]

    new_test_event.set()   # wake the main loop

def generation_done_callback(result):
    global newly_finished_tests, all_done_tests, all_done_instructions
    elf_path, instruction_count = result
    with callback_lock:
        newly_finished_tests += 1
        all_done_tests += 1
        all_done_instructions += instruction_count
        print(f"Generated ELF: {elf_path} ({all_done_tests} total)", flush=True)
    new_test_event.set()


def error_handler(e, memsize, design_name, process_instance_id, num_bbs, authorize_privileges):
    """
    Error handler for both line and br cov
    """
    global newly_finished_tests, callback_lock
    
    with callback_lock:
        print("\n========== WORKER ERROR ==========", flush=True)
        print(f"memsize: {memsize}, design_name: {design_name}, random seed: {process_instance_id}, num_bbs: {num_bbs}, authorize_privileges: {authorize_privileges}", flush=True)
        print(e, flush=True)
        traceback.print_exception(type(e), e, e.__traceback__)
        print("==================================\n", flush=True)
        newly_finished_tests += 1
    
    new_test_event.set()
    

def task_distribute(design_name: str, num_cores: int, seed_offset: int,
                    can_authorize_privileges: bool, no_update: bool = False,
                    generate_only: bool = False):
    global newly_finished_tests, merged_cov_datas, line_cov_data, all_done_tests
    global all_done_instructions, global_instr_prob, start_time

    cov_state = None if generate_only else CovState()
    newly_finished_tests = all_done_tests = all_done_instructions = 0
    merged_cov_datas.clear()
    _cov_log_records.clear()
    line_cov_data = ""
    new_test_event.clear()
    global_instr_prob = dict(ISAInstClass_Initial_Boosters)
    start_time        = time.time()
    last_clean_time   = time.time()
    previous_instructions = 0
    rebalancer = None if generate_only or no_update or design_name == "xiangshan" else CYWRRebalancer(global_instr_prob)
    done_callback = generation_done_callback if generate_only else test_done_callback
    operation = "ELF generation" if generate_only else "testing"
    print(f"Starting parallel {operation} of `{design_name}` on {num_cores} processes.")
    print(f"Instruction updates: {'enabled' if rebalancer is not None else 'disabled'}")

    # spike preparation
    calibrate_spikespeed()

    # for can_authorize_privileges == 1
    # xiangshan will jump 
    if not generate_only and can_authorize_privileges == True and design_name != "xiangshan":
        profile_get_medeleg_mask(design_name)

    # fuzzing warmup
    if not generate_only:
        warmup(design_name)
    if rebalancer is not None:
        rebalancer.update(compute_category_ratios(
            get_merged_line_cov_path(design_name), design_name), 0)

    # First round distribution
    pool = mp.Pool(processes=num_cores)
    process_instance_id = seed_offset
    for _ in range(num_cores):
        # config memsize and num_bbs
        memsize, _, _, num_bbs, authorize_privileges = gen_new_test_instance(design_name, process_instance_id, can_authorize_privileges)
        err_package = partial(error_handler, memsize=memsize, design_name=design_name, process_instance_id=process_instance_id, num_bbs=num_bbs, authorize_privileges=authorize_privileges)
        pool.apply_async(gen_testcases,
                         args=(memsize, design_name, process_instance_id,
                               num_bbs, authorize_privileges),
                         kwds={"instr_prob": dict(global_instr_prob),
                               "return_instruction_count": True,
                               "generate_only": generate_only},
                         callback=done_callback,
                         error_callback=err_package)
        process_instance_id += 1

    # Check the instruction epoch before new work, independently of timed reporting.
    try:
        while True:
            new_test_event.wait(timeout=30)
            with callback_lock:
                new_test_event.clear()
                if not generate_only and design_name != "xiangshan" and time.time() - last_clean_time >= PRINT_COV_TIME:
                    _do_coverage_merge(cov_state, design_name, start_time)
                    _flush_cov_log(design_name, no_update)
                    last_clean_time = time.time()

                epoch_instructions = all_done_instructions - previous_instructions
                if rebalancer is not None and epoch_instructions >= rebalancer.epoch_instructions:
                    next_prob = rebalancer.update(compute_category_ratios(
                        get_merged_line_cov_path(design_name), design_name), epoch_instructions)
                    if next_prob is not None:
                        global_instr_prob = next_prob
                        print(f"[CYWR] After {all_done_instructions} instructions: "
                              f"{rebalancer.category_weights}")
                    previous_instructions = all_done_instructions

                for _ in range(newly_finished_tests):
                    memsize, _, _, num_bbs, authorize_privileges = gen_new_test_instance(design_name, process_instance_id, can_authorize_privileges)
                    err_package = partial(error_handler, memsize=memsize, design_name=design_name, process_instance_id=process_instance_id, num_bbs=num_bbs, authorize_privileges=authorize_privileges)
                    pool.apply_async(gen_testcases,
                                     args=(memsize, design_name,
                                           process_instance_id, num_bbs,
                                           authorize_privileges),
                                     kwds={"instr_prob": dict(global_instr_prob),
                                           "return_instruction_count": True,
                                           "generate_only": generate_only},
                                     callback=done_callback,
                                     error_callback=err_package)
                    process_instance_id += 1
                newly_finished_tests = 0
    finally:
        pool.terminate()
        pool.join()
        if not generate_only and design_name != "xiangshan" and line_cov_data:
            with callback_lock:
                _do_coverage_merge(cov_state, design_name, start_time)
            _flush_cov_log(design_name, no_update)

def gen_testcases(  memsize: int, 
                    design_name: str, 
                    randseed: int,
                    nmax_bbs: int, 
                    authorize_privileges: bool, 
                    max_num_instructions: int  = None, 
                    check_pc_spike_again: bool = False,
                    instr_prob: dict = None,
                    return_instruction_count: bool = False,
                    generate_only: bool = False,
                    ):
    
    random.seed(randseed) 

    global start_time
    time_elaps = time.time() - start_time
    effective_prob = global_instr_prob if instr_prob is None else instr_prob

    # no_dependency_bias means we pick reg in same prob. and vice versa
    no_dependency_bias = random.random() < 0.5

    # ------------------------------
    # Enable elf lists
    # ------------------------------
    if not generate_only and enable_elf_lists and random.random() < 0.1 and time_elaps > 0: 
        fuzzerstate = FuzzerState(design_name, 
                            get_design_boot_addr(design_name), 
                            memsize, 
                            randseed,
                            nmax_bbs, 
                            authorize_privileges, 
                            effective_prob,
                            -1, 
                            no_dependency_bias)

        directory_path = str(get_riscv_dv_elfs_dir())
        elf_files = [f for f in os.listdir(directory_path) if f.endswith(".elf")]
        
        rtl_elfpath = os.path.join(directory_path, random.choice(elf_files))

        # run line_cov
        line_coverage_data = runtest_verilator_line_cov(fuzzerstate, rtl_elfpath)
        #run br_cov
        br_coverage_data = runtest_verilator_br_cov_elfs(design_name, rtl_elfpath)

    # ------------------------------
    # Default
    # ------------------------------
    else:
        fuzzerstate = FuzzerState(design_name, 
                                get_design_boot_addr(design_name), 
                                memsize, 
                                randseed,
                                nmax_bbs, 
                                authorize_privileges, 
                                effective_prob,
                                max_num_instructions,
                                no_dependency_bias)

        if generate_only:
            fuzzerstate.medeleg_mask = SPIKE_MEDELEG_MASK

        gen_basicblocks(fuzzerstate)

        expected_regvals = spike_resolution(fuzzerstate, check_pc_spike_again)
        rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'rtl', fuzzerstate.instance_to_str(), fuzzerstate.design_base_addr)

        if generate_only:
            if return_instruction_count:
                return rtl_elfpath, fuzzerstate.get_num_fuzzing_instructions_sofar()
            return rtl_elfpath

        if design_name == "xiangshan":
            subprocess.run([f"{get_xiangshan_emu_path()} -i {rtl_elfpath} --diff={get_xiangshan_nemu_path()}"], shell=True, check=True)
            if NO_REMOVE_TMPFILES == True:
                print(f"successful run rtl_path: {rtl_elfpath}\n\n")
            else :
                os.remove(rtl_elfpath)
            result = ({'br_cov': {0: '1'}, 'cond_cov': {0: '1'}}, "(1/1) 100.00%")
            return result + (fuzzerstate.get_num_fuzzing_instructions_sofar(),) if return_instruction_count else result

        # Validate the program before merging its statement coverage.
        is_mismatch, rtl_msg, br_coverage_data = runtest_verilator_br_cov(fuzzerstate, rtl_elfpath, expected_regvals)
        if is_mismatch == True:
            raise Exception(rtl_msg)

        line_coverage_data = runtest_verilator_line_cov(fuzzerstate, rtl_elfpath)

    result = (br_coverage_data, line_coverage_data)
    return result + (fuzzerstate.get_num_fuzzing_instructions_sofar(),) if return_instruction_count else result


def warmup(design_name):
    if design_name == "xiangshan":
        return 
    global merged_cov_datas, line_cov_data
    elf_path = str(get_warmup_elf_path())

    br_cov = eval(runtest_verilator_br_cov_elfs(design_name, elf_path))
    merged_cov_datas.append(br_cov)

    phony_fuzzerstate = FuzzerState (design_name, 0, 0, 0, 0, 0, global_instr_prob)
    phony_fuzzerstate.nmax_instructions = -1
    line_cov_data = runtest_verilator_line_cov(phony_fuzzerstate, elf_path)
