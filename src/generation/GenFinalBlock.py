from rv.csrids import CSR_IDS
from initialstate.PrivilegeState import PrivilegeStateEnum
from generation.Instructions import ISAInstrClass
from generation.InstructionsCfClass import ImmRdInstruction, RegImmInstruction, IntStoreInstruction, FloatStoreInstruction, JALInstruction, SpecialInstruction, CSRRegInstruction
from generation.InstructionsCfClass import JALInstruction, JALRInstruction, BranchInstruction, PrivilegeDescentInstruction, ExceptionInstruction
from generation.InstructionsCfClass import XiangShanInstrution
from initialstate.FuzzerState import FuzzerState

from params.fuzzparams import RDEP_MASK_REGISTER_ID, MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS, FPU_ENDIS_REGISTER_ID, TRAP_HANDLER_TMP_ID, SPP_ENDIS_REGISTER_ID
from params.runparams import DO_ASSERT

from common.GetCfgs import is_design_32bit, get_design_stop_sig_addr, get_design_reg_dump_addr, design_has_float_support, get_design_fpreg_dump_addr
from generation.Instructions import get_range_bits_per_instrclass
from common.utils import li_into_reg


FINAL_MACHINE_CSRS = (CSR_IDS.MSTATUS, CSR_IDS.MIE, CSR_IDS.MTVEC,
                      CSR_IDS.MSCRATCH, CSR_IDS.MEPC, CSR_IDS.MCAUSE, CSR_IDS.MINSTRET)
FINAL_DELEGATION_CSRS = (CSR_IDS.MEDELEG, CSR_IDS.MIDELEG)
FINAL_SUPERVISOR_CSRS = (CSR_IDS.SSTATUS, CSR_IDS.SIE, CSR_IDS.STVEC,
                         CSR_IDS.SSCRATCH, CSR_IDS.SEPC, CSR_IDS.SCAUSE, CSR_IDS.SATP)
FINAL_FLOAT_CSRS = (CSR_IDS.FFLAGS, CSR_IDS.FRM, CSR_IDS.FCSR)


def get_finalblock_max_size():
    num_csrs = len(FINAL_MACHINE_CSRS + FINAL_DELEGATION_CSRS + FINAL_SUPERVISOR_CSRS + FINAL_FLOAT_CSRS)
    return (22 + 2*MAX_NUM_PICKABLE_REGS + 2*MAX_NUM_PICKABLE_FLOATING_REGS - 1 + 3*num_csrs) * 4


def pop_last_bbs_to_connect_with_final_block(fuzzerstate: 'FuzzerState'):
    """
    This function is a bit tricky. The objective is to remove the final basic blocks until we find a basic block that can reach the final block. For example, a far JAL may not be able to reach the final block.
    This should be done once all the basic blocks have been inserted until a stop condition was met, such as no more space found for another bb, or memory usage above a certain percentage.
    
    Return:
        True iff the insertion succeeded. If False, the whole test case generation is considered failed.
    """
    popped_at_least_once = False
    while fuzzerstate.instr_objs_seq:
        # Check whether the last element can target the final bb
        bb_id                   = len(fuzzerstate.instr_objs_seq) - 1
        so_far_comp_instr       = fuzzerstate.bb_compressed_count[bb_id] - fuzzerstate.instr_objs_seq[bb_id][-1].iscompressed
        last_cf_instr_base_addr = fuzzerstate.bb_start_addr_seq[-1] + (len(fuzzerstate.instr_objs_seq[-1])-1) * 4 - so_far_comp_instr * 2 # HAS_COMPRESSED
        if isinstance(fuzzerstate.instr_objs_seq[-1][-1], JALInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.JAL)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], JALRInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.JALR)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], BranchInstruction) and fuzzerstate.instr_objs_seq[-1][-1].plan_taken:
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.BRANCH)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], PrivilegeDescentInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.DESCEND_PRV)
        elif isinstance(fuzzerstate.instr_objs_seq[-1][-1], ExceptionInstruction):
            range_bits = get_range_bits_per_instrclass(ISAInstrClass.EXCEPTION)
        else:
            instr = fuzzerstate.instr_objs_seq[-1][-1].instr_str
            raise ValueError(f"Unexpectedly got instruction: {instr}")
        if fuzzerstate.final_bb_base_addr >= last_cf_instr_base_addr - (1 << range_bits) and fuzzerstate.final_bb_base_addr < last_cf_instr_base_addr + (1 << range_bits):
            # The last basic block of the series is a candidate for jumping to the final block.
            # The target address of the last cf instruction will be injected later.
            if popped_at_least_once:
                fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            return True
        # else, in case the last block could not reach the final block, then we discard it and try with the previous one.
        popped_at_least_once = True
        fuzzerstate.instr_objs_seq.pop()
        fuzzerstate.bb_start_addr_seq.pop()
        fuzzerstate.saved_reg_states.pop()
    return False


# We must instantiate it in the end because we must know whether we have the privileges to turn on the FPU.
# Returns the instruction objects of the tail basic block
def finalblock(fuzzerstate: 'FuzzerState', design_name: str):
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

    ret = []
    if design_name == "xiangshan":
        ret += [
            RegImmInstruction("addi", 10, 0, 0, True),       # li a0, 1
            XiangShanInstrution("finish")                    # .word 0x5006b
        ]
        return ret

    is_design_64bit = not is_design_32bit(design_name)
    design_has_fpu = design_has_float_support(design_name)
    design_has_fpud = design_has_float_support(design_name)

    fuzzerstate.final_csr_ids = []
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        fuzzerstate.final_csr_ids.extend(FINAL_MACHINE_CSRS)
        if fuzzerstate.design_has_supervisor_mode:
            fuzzerstate.final_csr_ids.extend(FINAL_DELEGATION_CSRS)
    if fuzzerstate.design_has_supervisor_mode and fuzzerstate.privilegestate.privstate >= PrivilegeStateEnum.SUPERVISOR:
        fuzzerstate.final_csr_ids.extend(FINAL_SUPERVISOR_CSRS)
    if design_has_fpu and fuzzerstate.is_fpu_activated:
        fuzzerstate.final_csr_ids.extend(FINAL_FLOAT_CSRS)

    if CSR_IDS.MINSTRET in fuzzerstate.final_csr_ids:
        # Snapshot before the dump instructions increment minstret.
        ret += [
            CSRRegInstruction("csrrs", TRAP_HANDLER_TMP_ID, 0, CSR_IDS.MINSTRET),
            RegImmInstruction("addi", SPP_ENDIS_REGISTER_ID, TRAP_HANDLER_TMP_ID, 0, is_design_64bit),
        ]

    if fuzzerstate.vm_enabled and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        # Keep final MMIO dumps physical even when MPRV uses a lower privilege.
        ret += [
            ImmRdInstruction("lui", TRAP_HANDLER_TMP_ID, 0x20, is_design_64bit),
            CSRRegInstruction("csrrc", TRAP_HANDLER_TMP_ID, TRAP_HANDLER_TMP_ID, CSR_IDS.MSTATUS),
        ]

    # -------------------------------------------------------------------------
    # Dump registers
    # -------------------------------------------------------------------------
    lui_imm_regdump, addi_imm_regdump = li_into_reg(regdump_addr)

    # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # Compute the register dump address
    ret += [
        ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_regdump, is_design_64bit),
        RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_regdump, is_design_64bit)
    ]

   # Store the register values to the register dump address
    ret.append(SpecialInstruction("fence")) # Hopefully this prevents speculative execution of the stores
    for reg_id in range(1, MAX_NUM_PICKABLE_REGS):
        ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, reg_id, 0, -1, is_design_64bit))
        ret.append(SpecialInstruction("fence"))

    # Append CSR values to the integer dump before enabling the FPU changes mstatus.
    for csr_id in fuzzerstate.final_csr_ids:
        if csr_id == CSR_IDS.MINSTRET:
            ret.append(RegImmInstruction("addi", 1, SPP_ENDIS_REGISTER_ID, 0, is_design_64bit))
        elif csr_id == CSR_IDS.MSTATUS and fuzzerstate.vm_enabled:
            # The MPRV clear saved the original mstatus in the trap scratch register.
            ret.append(RegImmInstruction("addi", 1, TRAP_HANDLER_TMP_ID, 0, is_design_64bit))
        else:
            ret.append(CSRRegInstruction("csrrs", 1, 0, csr_id))
        ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 1, 0, -1, is_design_64bit))
        ret.append(SpecialInstruction("fence"))

    # Store the floating values as well, if FPU is supported and if there is no risk of it being deactivated
    if design_has_fpu and not fuzzerstate.is_fpu_activated:
        # Check that the fpregdump addr is correctly positioned
        if DO_ASSERT:
            assert get_design_fpreg_dump_addr(design_name) == regdump_addr + 8, f"We make the assumption that the FP regdump addr is the int regdump address + 8. However, currently, they are respectively {hex(get_design_fpreg_dump_addr(design_name))} and regdump_addr={hex(regdump_addr)}"
        if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
            # Enable the FPU
            ret.append(CSRRegInstruction("csrrw", 0, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS))
            fuzzerstate.is_fpu_activated = True
        if fuzzerstate.is_fpu_activated:
            for reg_id in range(MAX_NUM_PICKABLE_FLOATING_REGS):
                ret.append(FloatStoreInstruction("fsd" if design_has_fpud else "fsw", RDEP_MASK_REGISTER_ID, reg_id, 8, -1, is_design_64bit))
                ret.append(SpecialInstruction("fence"))

    # -------------------------------------------------------------------------
    # Stop request
    # -------------------------------------------------------------------------
    lui_imm_stopreq, addi_imm_stopreq = li_into_reg(stopsig_addr)

    # We re-purpose RDEP_MASK_REGISTER_ID, because we will not need it anymore.
    # Compute the stop request address
    ret += [
        ImmRdInstruction("lui", RDEP_MASK_REGISTER_ID, lui_imm_stopreq, is_design_64bit),
        RegImmInstruction("addi", RDEP_MASK_REGISTER_ID, RDEP_MASK_REGISTER_ID, addi_imm_stopreq, is_design_64bit)
    ]

    # Store the register values to the register dump address
    ret.append(IntStoreInstruction("sd" if is_design_64bit else "sw", RDEP_MASK_REGISTER_ID, 0, 0 & 0xFFFF, -1, is_design_64bit))
    ret.append(SpecialInstruction("fence"))

    # Infinite loop in the end of the simulation
    ret.append(JALInstruction("jal", 0, fuzzerstate.is_design_64bit, 0))

    if DO_ASSERT:
        assert len(ret) * 4 <= get_finalblock_max_size(), f"The final block is larger than expected: {len(ret) * 4} > {get_finalblock_max_size()}"

    return ret

# Spike does not support writing to some signaling addresses, but at the same time, we do not need it for spike resolution anyway. So let's replace it with an infinite loop.
def finalblock_spike_resolution(fuzzerstate: 'FuzzerState'):
    # Infinite loop in the end of the simulation
    return [JALInstruction("jal", 0, fuzzerstate.is_design_64bit, 0)]
