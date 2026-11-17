import itertools
import os
import subprocess
from pathlib import Path
from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES, PATH_TO_TMP, IS_DEBUG
from functools import cache


SPIKE_MEDELEG_MASK = 0xb3ff
SPIKE_STARTADDR = 0x80000000

FPREG_ABINAMES = [
    'ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7', 'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5', 'fa6', 'fa7', 'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7', 'fs8', 'fs9', 'fs10', 'fs11', 'ft8', 'ft9', 'ft10', 'ft11'
]

def __get_all_regs_from_spike_out(spike_out: str, is_design_64bit: bool):
    ret = [0 for i in range(32)]
    zero_index = spike_out.index(b'zero: 0x')+8
    # First row (ignore 0)
    for col_id in range(4):
        curr_index_in_ret = col_id
        curr_index_in_spikeout = zero_index + (16+8*int(is_design_64bit))*col_id
        ret[curr_index_in_ret] = int(spike_out[curr_index_in_spikeout:curr_index_in_spikeout+8+8*int(is_design_64bit)].decode('ascii'), base=16)
    # The 7 other rows
    for row_id in range(1, 8):
        row_start_index = (65+32*int(is_design_64bit))*row_id+zero_index
        for col_id in range(4):
            curr_index_in_ret = (row_id << 2) + col_id
            curr_index_in_spikeout = row_start_index + (16+8*int(is_design_64bit))*col_id
            ret[curr_index_in_ret] = int(spike_out[curr_index_in_spikeout:curr_index_in_spikeout+8+8*int(is_design_64bit)].decode('ascii'), base=16)
    return ret

def __gen_spike_dbgcmd_file_for_trace_regs_at_pc_locs(identifier_str: str, startpc: int, regdump_reqs, dump_final_reg_vals: bool, final_addr: int, num_fp_regs: int, dump_freg_format: str = '', final_csr_ids = ()):
    """
    Generate the spike debug command file (as understood by spike --debug-cmd) and returns its path.
    This command file will prompt the required registers at the required pc locations

    Args:
        regdump_reqs: an ordered (in program order, NOT necessarily in increasing PC order) list of tuples 
            (pc_to_req, tuple of registers to prompt). The register is dumped before the instruction at that PC 
            is executed. Note: we currently do not use producer/consumer instructions for branches. If the third 
            element of the tuple is 'priv', then we do not dump a register value or a CSR value, but the privilege mode.
        dump_freg_format either '' or 'd' for 'fregd' or 's' for 'fregs'
    
    """
    assert not dump_freg_format # This assertion is to check whether we actually can remove dump_freg_format.
    path_to_debug_file = os.path.join(PATH_TO_TMP, 'dbgcmds', f"cmds_trace_regs_at_pc_locs_{identifier_str}")
    # if not os.path.exists(path_to_debug_file):
    Path(os.path.dirname(path_to_debug_file)).mkdir(parents=True, exist_ok=True)
    spike_debug_commands = [
        f"until pc 0 0x{startpc:x}"
    ]
    prev_req_pc = -1 # Just make sure it won't coincide with the first requested pc.
    for next_pc, is_float_req, reg_to_dump in regdump_reqs:
        # The surrounding condition on permits to get multiple registers in the same PC, without issuing an useless `until`. This is useful for non-taken branches, for example, in which we need to know the values of both operands.
        if prev_req_pc != next_pc:
            spike_debug_commands.append(f"until pc 0 0x{startpc+next_pc:x}")
            prev_req_pc = next_pc
        # No elif here!
        if reg_to_dump == 'priv':
            spike_debug_commands.append('priv 0')
        else:
            spike_debug_commands.append(f"{'f' if is_float_req else ''}reg 0 {reg_to_dump}")
        # spike_debug_commands.append('pc 0')
    if dump_final_reg_vals:
        spike_debug_commands.append(f"until pc 0 0x{final_addr:x}")
        spike_debug_commands.append('reg 0')
        for fp_reg_id in range(num_fp_regs):
            spike_debug_commands.append(f"freg 0 {FPREG_ABINAMES[fp_reg_id]}")
        if dump_freg_format:
            for fp_reg_id in range(num_fp_regs):
                spike_debug_commands.append(f"freg{dump_freg_format} 0 {FPREG_ABINAMES[fp_reg_id]}")
        for csr_id in final_csr_ids:
            spike_debug_commands.append(f"reg 0 {csr_id.name.lower()}")
    spike_debug_commands.append('q\n')
    spike_debug_commands_str = '\n'.join(spike_debug_commands)

    # print(spike_debug_commands_str)
    with open(path_to_debug_file, 'w') as f:
        f.write(spike_debug_commands_str)

    return path_to_debug_file

# @brief Generate the spike debug command file (as understood by spike --debug-cmd) and returns its path.
# This command file will prompt the PC at every cycle
def __gen_spike_dbgcmd_file_for_trace_pcs(identifier_str: str, numinstrs: int, startpc: int, dump_final_reg_vals: bool, num_fp_regs: int):
    path_to_debug_file = os.path.join(PATH_TO_TMP, 'dbgcmds', f"cmds_trace_pcs_{identifier_str}")
    # if not os.path.exists(path_to_debug_file):
    Path(os.path.dirname(path_to_debug_file)).mkdir(parents=True, exist_ok=True)
    spike_debug_commands = [
        f"until pc 0 0x{startpc:x}"
    ]
    for _ in range(numinstrs):
        spike_debug_commands.append('r 1')
        # spike_debug_commands.append('pc 0')
    if dump_final_reg_vals:
        spike_debug_commands.append('r 1')
        spike_debug_commands.append('reg 0')
        if num_fp_regs:
            for fp_reg_id in range(num_fp_regs):
                spike_debug_commands.append(f"freg 0 {FPREG_ABINAMES[fp_reg_id]}")
    spike_debug_commands.append('q\n')
    spike_debug_commands_str = '\n'.join(spike_debug_commands)

    with open(path_to_debug_file, 'w') as f:
        f.write(spike_debug_commands_str)

    return path_to_debug_file

def run_trace_regs_at_pc_locs(identifier_str: str, elfpath: str, rvflags: str, startpc: int, regdump_reqs, dump_final_reg_vals: bool, final_addr: int, num_fp_regs: int, has_fpdouble_support: bool, dump_freg_format: str = '', final_csr_ids = ()) -> list:
    """
    Runs and traces every PC location.

    Args:
        regdump_reqs: see __gen_spike_dbgcmd_file_for_trace_regs_at_pc_locs
        dump_freg_format either '' or 'd' for 'fregd' or 's' for 'fregs'
    
    Returns:
        list of register values. If dump_final_reg_vals is True, then the output is a pair, whose second element contains final int and float register arrays and a CSR value dictionary
    """
    
    if DO_ASSERT:
        assert '32' in rvflags or '64' in rvflags

    path_to_debug_file = __gen_spike_dbgcmd_file_for_trace_regs_at_pc_locs(identifier_str, startpc, regdump_reqs, dump_final_reg_vals, final_addr, num_fp_regs, dump_freg_format, final_csr_ids)
    # Second, run the Spike command
    spike_shell_command = (
        "spike",
        "-d",
        f"--debug-cmd={path_to_debug_file}",
        f"--isa={rvflags}",
        f"--pc={startpc}",
        elfpath
    )

    if IS_DEBUG:
        print(f"Spike debug file:           {path_to_debug_file}")

    try:
        spike_out = subprocess.run(spike_shell_command, capture_output=True, timeout=get_spike_timeout_seconds()).stderr
    except Exception as e:
        raise Exception(f"Spike timeout (A) for identifier str: {identifier_str}. Command: {' '.join(filter(lambda s: '--debug-cmd' not in s, spike_shell_command))}  Debug file: {path_to_debug_file}")
    if not NO_REMOVE_TMPFILES: 
        os.remove(path_to_debug_file)
        del path_to_debug_file

    addr_str_splitted = spike_out.split(b"\n")
    addr_str_splitted = list(filter(lambda s: b'exception' not in s, addr_str_splitted))

    ret = []
    for dumpreq_id in range(len(regdump_reqs)):
        if addr_str_splitted[dumpreq_id+1][:2] == b'0x':
            ret.append(int(addr_str_splitted[dumpreq_id+1][2:], base=16))
        elif len(addr_str_splitted[dumpreq_id+1]) == 1:
            # This should be a privilege dump
            if DO_ASSERT:
                assert chr(addr_str_splitted[dumpreq_id+1][0]) in ('M', 'S', 'U'), f"Found a single character, but did not expect it to be {chr(addr_str_splitted[dumpreq_id+1][0])}."
            ret.append(chr(addr_str_splitted[dumpreq_id+1][0]))
        else:
            raise NotImplementedError(f"Line not supported: {addr_str_splitted[dumpreq_id+1]} -- previous line is {addr_str_splitted[dumpreq_id]}.")

    # Potentially get the final register values
    if dump_final_reg_vals:
        final_intreg_vals = __get_all_regs_from_spike_out(spike_out, '64' in rvflags)
        final_fpureg_vals = []
        final_csr_vals = {}
        if final_csr_ids:
            csr_rows = spike_out.splitlines()[-len(final_csr_ids):]
            for csr_id, csr_row in zip(final_csr_ids, csr_rows):
                if not csr_row.startswith(b'0x'):
                    raise ValueError(f"Missing Spike CSR {csr_id.name.lower()}: {csr_row!r}")
                final_csr_vals[csr_id] = int(csr_row, 16)
        # Get the FPU regs
        if num_fp_regs:
            # Find the base for the FPU reg dumps
            for row_id in itertools.count(len(regdump_reqs) + 8):
                if addr_str_splitted[row_id][:10] == b'0xffffffff':
                    fp_base_row_addr = row_id
                    break
            for fp_reg_id in range(num_fp_regs):
                final_fpureg_vals.append(int(addr_str_splitted[fp_base_row_addr+fp_reg_id][18+8*int(not has_fpdouble_support):], 16))
            if dump_freg_format:
                final_fpureg_archvals = []
                for fp_reg_id in range(num_fp_regs):
                    final_fpureg_archvals.append(addr_str_splitted[fp_base_row_addr+num_fp_regs+fp_reg_id])
                return ret, (final_intreg_vals, final_fpureg_vals, final_fpureg_archvals, final_csr_vals)
        return ret, (final_intreg_vals, final_fpureg_vals, final_csr_vals)
    else:
        return ret
    


###
# Timeout Management
###

SPIKE_TIMEOUT_SLACK_FACTOR = 1000 # We automatically add this factor to the timeout, to account for the fact that the spike speed is not perfectly calibrated or the subprocess may require some more time in a busy system.
__spike_ns_per_instr = None

def _get_spike_ns_per_instr() -> int:
    if __spike_ns_per_instr is None:
        raise Exception('Spike speed not calibrated yet.')
    return __spike_ns_per_instr

def get_spike_timeout_seconds() -> int:
    return max((SPIKE_TIMEOUT_SLACK_FACTOR*_get_spike_ns_per_instr())/1e9, 5)

@cache
def calibrate_spikespeed(numinstrs:int = 10000) -> list:
    """
    brief Runs a spike instance and returns the average nanoseconds per instruction.
    """
    global __spike_ns_per_instr
    from generation.GenElf import gen_elf
    from rv.rv32i import rv32i_jal
    from time import time_ns

    # First, create the file that contains the commands, if it does not already exist
    path_to_debug_file = __gen_spike_dbgcmd_file_for_trace_pcs('spikespeedcalibration', numinstrs, SPIKE_STARTADDR, True, 16)

    # Second, generate a dummy ELF file containing an infinite loop
    elfpath = os.path.join(PATH_TO_TMP, 'spikespeedcalibration.elf')
    # generaged elf only have one instr j xx
    gen_elf(rv32i_jal(0, 0).to_bytes(4, 'little'), SPIKE_STARTADDR, SPIKE_STARTADDR, elfpath, False)

    # Run the Spike command
    spike_shell_command = (
        "spike",
        "-d",
        f"--debug-cmd={path_to_debug_file}",
        f"--isa={'rv32i'}",
        f"--pc={SPIKE_STARTADDR}",
        elfpath
    )

    ns_before = time_ns()
    subprocess.run(spike_shell_command, capture_output=True)
    ns_elapsed = time_ns()-ns_before

    if not NO_REMOVE_TMPFILES:
        os.remove(path_to_debug_file)
        os.remove(elfpath)
        del path_to_debug_file
        del elfpath

    __spike_ns_per_instr = ns_elapsed / numinstrs