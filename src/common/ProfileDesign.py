# This script provides a facility to profile designs in terms of:
# - Supported medeleg bits
# - WLRL behavior for writes to mcause (we assume that the behavior is the same for scause)

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from common.utils import li_into_reg
from common.GetCfgs import get_design_boot_addr, is_design_32bit, get_design_stop_sig_addr, get_design_reg_dump_addr
from params.fuzzparams import RDEP_MASK_REGISTER_ID
from params.runparams import NO_REMOVE_TMPFILES
from generation.InstructionsCfClass import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, CSRImmInstruction, CSRRegInstruction, SpecialInstruction
from generation.GenElf import gen_elf_from_bbs
from initialstate.FuzzerState import FuzzerState
from run_verilator import runtest_verilator_forprofiling

###
# Internal functions
###

# The snippet will dump a register value of the medeleg when fed with ones and then read back
# @param design_name: the name of the design to profile
# @return a snippet that dumps the register value
def __gen_medeleg_profiling_snippet(design_name: str):
    # Get some info about the design
    try:
        stopsig_addr = get_design_stop_sig_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `stopsigaddr` attribute.")
    try:
        regdump_addr = get_design_reg_dump_addr(design_name)
    except:
        raise ValueError(f"Design `{design_name}` does not have the `regdumpaddr` attribute.")

    if DO_ASSERT:
        assert regdump_addr < 0x80000000, f"For the destination address `{hex(regdump_addr)}`, we will need to manage sign extension, which is not yet implemented here."
        assert stopsig_addr < 0x80000000, f"For the destination address `{hex(stopsig_addr)}`, we will need to manage sign extension, which is not yet implemented here."

    # We use the fuzzerstate for convenience but use very few of its features for this function's purposes. In particular, we do not bother about memviews.
    fuzzerstate = FuzzerState(design_name, get_design_boot_addr(design_name), 1 << 16, 0, 1, True)

    fuzzerstate.reset()
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    is_design_64bit = not is_design_32bit(design_name)

    ###
    # Write -1 into medeleg, then read it back
    ###

    # Write full ones into the medeleg register
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", 1, 0, -1, is_design_64bit))
    
    fuzzerstate.instr_objs_seq[-1].append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.MEDELEG))
    
    # Read medeleg into register 1.
    fuzzerstate.instr_objs_seq[-1].append(CSRImmInstruction("csrrwi", 1, 0, CSR_IDS.MEDELEG))

    # Dump the register
    lui_imm, addi_imm = li_into_reg(regdump_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm, is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1, is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction("fence"))

    # Quit the simulation
    lui_imm, addi_imm = li_into_reg(stopsig_addr)
    fuzzerstate.instr_objs_seq[-1].append(ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm, is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm, is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1, is_design_64bit))
    fuzzerstate.instr_objs_seq[-1].append(SpecialInstruction("fence"))

    return fuzzerstate


def __get_medeleg_mask(design_name: str):
    # The fuzzerstate contains the snippet that dumps a register value of 1 if an exception occurred, else a value of 0
    fuzzerstate = __gen_medeleg_profiling_snippet(design_name)
    rtl_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'medelegprofiling', design_name, fuzzerstate.design_base_addr)

    if NO_REMOVE_TMPFILES:
        print(f"Generate profiling elf: {rtl_elfpath}")

    return runtest_verilator_forprofiling(fuzzerstate, rtl_elfpath, 1)



# ------------------------------------------------------------------------------------------------------------
# 在 RISC-V 处理器中，medeleg（Machine Exception Delegation Register）是 mstatus 相关的一个 CSR，
# 将特定的异常从机器模式 (M-mode) 委托给监督模式 (S-mode)，从而允许操作系统处理异常，而不是直接由固件或硬件处理
# MASK determines which trap could be delegated
# ------------------------------------------------------------------------------------------------------------
PROFILED_MEDELEG_MASK = None
def profile_get_medeleg_mask(design_name: str):   
    global PROFILED_MEDELEG_MASK
    PROFILED_MEDELEG_MASK = __get_medeleg_mask(design_name)

def get_medeleg_mask(design_name: str):
    """
    Returns:
        the mask of medeleg bits that are supported by the design
    """
    if PROFILED_MEDELEG_MASK is None:
        if design_name == "xiangshan":
            # TODO I dont know xiangshan medeleg mask yet, so i use rocket's
            return 15775069
        else:
            raise Exception(f"Error: get_medeleg_mask was called before profiling when fuzzing {design_name}.")
    return PROFILED_MEDELEG_MASK
