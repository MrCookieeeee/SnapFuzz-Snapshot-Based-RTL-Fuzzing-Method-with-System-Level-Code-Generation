
import itertools
import subprocess
import fcntl
import os
import re
import threading
from typing import TYPE_CHECKING

from params.fuzzparams import MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS
from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES

from common.GetCfgs import design_has_float_support
from common.SetEnv import setup_sim_env
from common.TolerateBugs import is_tolerate_boom_minstret, is_tolerate_rocket_minstret
from rv.csrids import CSR_IDS
from common.path import (get_sim_executable_path, get_cov_txt_path,
                         get_merged_line_cov_path, get_bench_sim_path,
                         get_line_cov_sim_path, get_merged_line_cov_lock, get_merged_line_cov_tmp)
from coverage.CovState import collect_coverage

from common.utils import IntRegIndivState
from coverage import CovState
from generation.GenTrapHandlerBlocks import TRAP_INSTR

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState

wirte_merged_lock = threading.Lock()

# -------------------------------------------------------------------------------------------------------------
# The maximum number of cycles that we allow per run is MAX_CYCLES_PER_INSTR * num_instrs + SETUP_CYCLES.
# MAX_CYCLES_PER_INSTR was increased from 30 to 32 after some Rocket tests failed.
# -------------------------------------------------------------------------------------------------------------
MAX_CYCLES_PER_INSTR = 35
# -------------------------------------------------------------------------------------------------------------
# Without this, we had issues with BOOM with very short programs (typically <20 instructions) 
# not being able to finish in time.
# -------------------------------------------------------------------------------------------------------------
SETUP_CYCLES = 1000 
# -------------------------------------------------------------------------------------------------------------
# Extra overhead instructions per trap handler invocation (context save/restore + mepc advance + mret).
# -------------------------------------------------------------------------------------------------------------
TRAP_HANDLER_OVERHEAD_INSTRS = TRAP_INSTR
# -------------------------------------------------------------------------------------------------------------
# Estimated fraction of instructions that cause traps (page faults, illegal instrs, etc.)
# Conservative upper bound to prevent simulation timeouts.
# -------------------------------------------------------------------------------------------------------------
TRAP_RATE_ESTIMATE = 0.15
# -------------------------------------------------------------------------------------------------------------
# Additional init/final block instructions not counted in basic-block instruction lists.
# -------------------------------------------------------------------------------------------------------------
INIT_FINAL_OVERHEAD = 200


def compute_simlen(fuzzerstate: 'FuzzerState') -> int:
    """
    Compute a robust SIMLEN that accounts for init/final block overhead,
    trap handler invocations, and VM page-walk costs.
    
    The basic-block instruction count alone underestimates the actual cycles
    needed because it ignores:
      - Init block and final block instructions (~200 total)
      - Trap handler overhead (~50 instrs per invocation)
      - TLB refill costs after sfence.vma (page walks add ~100 extra cycles each)
    """
    num_bb_instrs = len(list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq)))
    estimated_traps = int(num_bb_instrs * TRAP_RATE_ESTIMATE)
    total_instrs = (num_bb_instrs + len(fuzzerstate.block_tail_instrs)
                    + INIT_FINAL_OVERHEAD + 2 + 3*len(fuzzerstate.final_csr_ids)
                    + estimated_traps * TRAP_HANDLER_OVERHEAD_INSTRS)
    simlen = total_instrs * MAX_CYCLES_PER_INSTR + SETUP_CYCLES

    # VM-enabled tests incur extra page-walk overhead after each sfence.vma.
    # Each page walk involves 3 sequential memory loads (~60 cycles on Rocket).
    if getattr(fuzzerstate, 'vm_enabled', False):
        simlen = int(simlen * 2)

    return simlen


def _csr_values_match(csr_id, expected, received, is_design_64bit):
    if expected == received:
        return True
    if csr_id not in (CSR_IDS.MSTATUS, CSR_IDS.SSTATUS):
        return False
    # The privileged ISA permits conservative FS tracking from Initial/Clean to Dirty.
    if ((expected >> 13) & 3) not in (1, 2) or ((received >> 13) & 3) != 3:
        return False
    sd_bit = 1 << (63 if is_design_64bit else 31)
    if (expected ^ received) & ~((3 << 13) | sd_bit):
        return False
    for value in (expected, received):
        dirty = any(((value >> shift) & 3) == 3 for shift in (9, 13, 15))
        if bool(value & sd_bit) != dirty:
            return False
    return True


def runtest_verilator_br_cov(fuzzerstate: 'FuzzerState', rtl_elfpath, expected_regvals):
    """
    For diff test
    """
    expected_intregvals, expected_floatregvals, expected_csrvals = expected_regvals
    del expected_regvals
   
    if DO_ASSERT:
        assert len(expected_intregvals) >= fuzzerstate.num_pickable_regs-1
        if fuzzerstate.design_has_fpu:
            assert len(expected_floatregvals) == fuzzerstate.num_pickable_floating_regs

    simlen = compute_simlen(fuzzerstate)

    is_stop_successful, received_regvals, coverage_data = runsim_verilator_br_cov(fuzzerstate.design_name, simlen, rtl_elfpath, fuzzerstate.num_pickable_regs-1, fuzzerstate.num_pickable_floating_regs, final_csr_ids=fuzzerstate.final_csr_ids)

    # Handle coveragedata
    if not is_stop_successful:
        return True, f"Timeout for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}` -- ({fuzzerstate.memsize}, design_name, {fuzzerstate.randseed}, {fuzzerstate.nmax_bbs})", None

    # Check that we retrieved the regs correctly
    if received_regvals is None:
        raise Exception(f"Missing all regs for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`")

    received_intregvals, received_floatregvals, received_csrvals = received_regvals
    del received_regvals

    if DO_ASSERT:
        assert len(received_intregvals) >= fuzzerstate.num_pickable_regs-1
        if fuzzerstate.design_has_fpu:
            assert len(received_floatregvals) == fuzzerstate.num_pickable_floating_regs, f"Wanted {fuzzerstate.num_pickable_floating_regs} floating regs. Got {len(received_floatregvals)}."

    # Compare the expected vs. received registers
    reg_mismatch = False
    ret_str_list_regmismatch = []
    for reg_id in range(fuzzerstate.num_pickable_regs-1):
        if expected_intregvals[reg_id] != received_intregvals[reg_id] and fuzzerstate.intregpickstate.get_regstate(reg_id+1) in (IntRegIndivState.FREE, IntRegIndivState.CONSUMED):
            reg_mismatch = True
            ret_str_list_regmismatch.append(f"Register mismatch (x{reg_id+1}) for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`. State: {fuzzerstate.intregpickstate.get_regstate(reg_id+1)}. Expected `{hex(expected_intregvals[reg_id])}`, got `{hex(received_intregvals[reg_id])}`.")

    if fuzzerstate.design_has_fpu:
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            # received_floatregvals[fp_reg_id] can be None if the FPU is disabled in the final block and the final permission level does not permit enabling it.
            if expected_floatregvals[fp_reg_id] != received_floatregvals[fp_reg_id] and received_floatregvals[fp_reg_id] is not None:
                reg_mismatch = True
                ret_str_list_regmismatch.append(f"Register mismatch (f{fp_reg_id}) for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`. Expected `{hex(expected_floatregvals[fp_reg_id])}`, got `{hex(received_floatregvals[fp_reg_id])}`.")
    
    for csr_id in fuzzerstate.final_csr_ids:
        if csr_id == CSR_IDS.MINSTRET:
            if (fuzzerstate.design_name == "boom" and is_tolerate_boom_minstret()) or \
               (fuzzerstate.design_name == "rocket" and is_tolerate_rocket_minstret()):
                continue
        if not _csr_values_match(csr_id, expected_csrvals[csr_id],
                                 received_csrvals[csr_id], fuzzerstate.is_design_64bit):
            reg_mismatch = True
            ret_str_list_regmismatch.append(f"CSR mismatch ({csr_id.name.lower()}, {hex(csr_id)}) for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`. Expected `{hex(expected_csrvals[csr_id])}`, got `{hex(received_csrvals[csr_id])}`.")

    rtl_msg = '\n  '.join(ret_str_list_regmismatch)

    if not NO_REMOVE_TMPFILES:
        os.remove(rtl_elfpath)
        del rtl_elfpath

    if reg_mismatch:
        return True, rtl_msg, coverage_data
    else:
        return False, rtl_msg, coverage_data
    
def runsim_verilator_br_cov(design_name, simlen, elfpath, num_int_regs: int = MAX_NUM_PICKABLE_REGS-1, num_float_regs: int = MAX_NUM_PICKABLE_FLOATING_REGS, coveragepath = None, get_rfuzz_coverage_mask = False, final_csr_ids = ()):
    """
    Run the RTL simulation and get regs vals     
    """
    if DO_ASSERT:
        assert coveragepath is None or not get_rfuzz_coverage_mask
    # Simulator executable: soc/V<design>_br_soc
    
    snapfuzzdir = '/'
    my_env = setup_sim_env(elfpath, '/dev/null', '/dev/null', simlen, snapfuzzdir, coveragepath, False)
    sim_executable_path  = str(get_sim_executable_path(design_name))
    
    # Run Verilator
    exec_out = subprocess.run([sim_executable_path], check=True, text=True, capture_output=True, env=my_env)
    # 过滤掉包含 'Writing ELF word to' 的行，并将剩下的行存储在 outlines 列表中
    outlines = list(filter(lambda l: 'Writing ELF word to' not in l, exec_out.stdout.split('\n')))    

    coverage_data = collect_coverage(exec_out.stdout)

    # Check stop success
    is_stop_successful = 'Found a stop request.' in exec_out.stdout
    if "medelegprofilingboom" in elfpath:
        if is_stop_successful and NO_REMOVE_TMPFILES :
            print(f"success run medelegprofiling:   {elfpath}")
    elif is_stop_successful and NO_REMOVE_TMPFILES :
            print(f"success run rtl_path br_cov:   {elfpath}")
    
    if not is_stop_successful:
        print(f"cant get br_cov")
        return False, None, coverage_data
    

    # Retrieve the register values
    ret_intregs = []
    ret_floatregs = []
    curr_index = 0
    for reg_id in range(1, num_int_regs+1):
        for row_id in itertools.count(curr_index):
            if len(outlines[row_id]) >= 19 and outlines[row_id][:19] == f"Dump of reg x{reg_id:02}: 0x":
                ret_intregs.append(int(outlines[row_id][19:35], 16))
                curr_index = row_id + 1
                break
    if design_has_float_support(design_name):
        for fp_reg_id in range(num_float_regs):
            for row_id in itertools.count(curr_index):
                if row_id >= len(outlines):
                    # This happens if the FPU is disabled in the final block and the final permission level does not permit enabling it.
                    ret_floatregs.append(None)
                    curr_index = row_id + 1
                    break
                if len(outlines[row_id]) >= 19 and outlines[row_id][:19] == f"Dump of reg f{fp_reg_id:02}: 0x":
                    ret_floatregs.append(int(outlines[row_id][19:35], 16))
                    curr_index = row_id + 1
                    break
    ret_csrs = {}
    if final_csr_ids:
        int_dumps = {int(reg_id): int(value, 16) for reg_id, value in re.findall(r'Dump of reg x(\d+): 0x([0-9a-fA-F]+)', exec_out.stdout)}
        for reg_id, csr_id in enumerate(final_csr_ids, MAX_NUM_PICKABLE_REGS):
            if reg_id not in int_dumps:
                raise ValueError(f"Missing CSR {csr_id.name.lower()} dump for {elfpath}")
            ret_csrs[csr_id] = int_dumps[reg_id]
    return True, (ret_intregs, ret_floatregs, ret_csrs), coverage_data


def runtest_verilator_line_cov(fuzzerstate: 'FuzzerState', elfpath):
    """
    For line_cov, we DON'T use differential test, because bugs can be found when doing br_cov test
    """
    # for ELF_Lists
    if fuzzerstate.nmax_instructions == -1:
        simlen = 15000 * MAX_CYCLES_PER_INSTR + SETUP_CYCLES
    else:
        simlen = compute_simlen(fuzzerstate)

    snapfuzzdir = '/'
    my_env = setup_sim_env(elfpath, '/dev/null', '/dev/null', simlen, snapfuzzdir, None, False)
    
    sim_executable_path  = get_line_cov_sim_path(fuzzerstate.design_name)
    
    exec_out = subprocess.run([sim_executable_path], check=True, text=True, capture_output=True, env=my_env)  
    
    # check the stop flag
    is_stop_successful = 'Found a stop request.' in exec_out.stdout
    if is_stop_successful:
        if  NO_REMOVE_TMPFILES :
            print(f"success run rtl_path line_cov: {elfpath}")
    else:
        raise RuntimeError("dont get line_cov")
    
    # handle line_cov info
    outlines = exec_out.stdout.splitlines()
    
    # NOTICE: line coverage info should starts after "Elapsed time:" line
    # SHOULD take care of this when building the soc
    idx = next(i for i, line in enumerate(outlines) if "Elapsed time:" in line)
    filtered_lines = outlines[idx+1:] 

    # 提取文件名 "rtlxx_boom_0_27.elf"
    filename = os.path.basename(elfpath)  #
    # 去掉后缀 "rtlxx_boom_0_27"
    cov_file = os.path.splitext(filename)[0]
    
    # write stdout to files
    single_line_cov_path = get_cov_txt_path(cov_file)
    with open(single_line_cov_path, "w") as f:
        f.write("\n".join(filtered_lines))

    # handle .dat cov files
    merged_line_cov_file      = get_merged_line_cov_path(fuzzerstate.design_name)
    merged_line_cov_file_lock = get_merged_line_cov_lock(fuzzerstate.design_name)
    merged_line_cov_file_tmp  = get_merged_line_cov_tmp(fuzzerstate.design_name)

    with open(merged_line_cov_file_lock, "w") as lock_file:
        # 加文件锁（阻塞，直到获取到锁）
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        merged_line_cov_file_tmp = str(merged_line_cov_file) + ".tmp"
        subprocess.run(
            ["verilator_coverage", "-write", merged_line_cov_file_tmp, merged_line_cov_file, single_line_cov_path],
            capture_output=True, text=True, check=True
        )
        
        # 原子替换
        os.replace(merged_line_cov_file_tmp, merged_line_cov_file)  
        # 释放锁
        fcntl.flock(lock_file, fcntl.LOCK_UN)


    result = subprocess.run(
        ["verilator_coverage", "--annotate", "/dev/null", merged_line_cov_file],
        capture_output=True, text=True
    )

    match = re.search(r"Total coverage\s*(\(\d+/\d+\)\s*\d+(?:\.\d+)?%)", result.stdout)
    if match:
        os.remove(single_line_cov_path)
        return match.group(1)
        # print("Total coverage:", match.group(1))
    else:
        raise RuntimeError("no match found")


def runtest_verilator_forprofiling(fuzzerstate, elfpath: str, expected_fuzzerstate_len_fordebug: int):
    """
    Runs the test and checks for a single dumped register.

    Return:
        the value of the dumped register
    """
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == expected_fuzzerstate_len_fordebug, f"Unexpected length of fuzzerstate: {len(fuzzerstate.instr_objs_seq)}"
    is_stop_successful, received_regvals, coverage_data = runsim_verilator_br_cov(fuzzerstate.design_name, len(fuzzerstate.instr_objs_seq[0])*MAX_CYCLES_PER_INSTR + SETUP_CYCLES, elfpath, 1, 0)
    # Check successful stop
    if not is_stop_successful:
        raise Exception(f"Timeout during profiling of design `{fuzzerstate.design_name}`.")
    # Check that we retrieved the regs correctly
    if received_regvals is None:
        raise Exception(f"Missing all regs for params: memsize: `{fuzzerstate.memsize}`, design_name: `{fuzzerstate.design_name}`, nmax_bbs: `{fuzzerstate.nmax_bbs}`, randseed: `{fuzzerstate.randseed}`")
    received_intregvals, received_floatregvals, _ = received_regvals
    del received_regvals
    if DO_ASSERT:
        assert len(received_intregvals) == 1
        assert len(received_floatregvals) == 0
    return received_intregvals[0]




def runtest_verilator_br_cov_elfs(design_name, elfpath):
    
    cmd = (
        "SIMLEN=500000 "
        f"SIMSRAMELF={elfpath} "
        f"{get_sim_executable_path(design_name)}"
    )
    exec_out = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    coverage_data = collect_coverage(exec_out.stdout)

    # Check stop success
    # Fault Handler
    is_stop_successful = 'Found a stop request.' in exec_out.stdout    
    if not is_stop_successful:
        raise Exception("\033[91mDIDN'T GET THE COV_DATA CHECK!\033[0m")

    return str(coverage_data)

def runsim_verilator_for_elf_lists(design_name, elfpath):
    
    cmd = (
        "SIMLEN=500000 "
        f"SIMSRAMELF={elfpath} "
        f"{get_bench_sim_path(design_name)}"
    )
    exec_out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    coverage_data = collect_coverage(exec_out.stdout)
    
    # Check stop success
    # Fault Handler
    is_stop_successful = 'Found a stop request.' in exec_out.stdout    
    if not is_stop_successful:
        raise Exception("\033[91mDIDN'T GET THE COV_DATA CHECK!\033[0m")

    return coverage_data
