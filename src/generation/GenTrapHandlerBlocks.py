import random

from initialstate.FuzzerState import FuzzerState
from generation.InstructionsCfClass import CSRRegInstruction, JALRInstruction, ImmRdInstruction, RegImmInstruction, JALInstruction, PrivilegeDescentInstruction, BranchInstruction, FloatLoadInstruction, IntLoadInstruction, FloatStoreInstruction, IntStoreInstruction
from rv.csrids import CSR_IDS
from common.utils import IntRegIndivState


from common.utils import li_into_reg, li_signed_into_reg
from pick.CreateInstr import create_instr


from params.fuzzparams import MAX_NUM_PICKABLE_REGS, TRAP_HANDLER_TMP_ID, MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID
from params.runparams import DO_ASSERT

TRAP_INSTR = 50


def get_trap_handler_block_size():
    return (TRAP_INSTR) * 4

def trap_handler_block(fuzzerstate: 'FuzzerState'):
    """
    Decide whether to end the program
        a. end     -> jump to final block
        b. not end -> jump to mepc

    Return:
        set of instrs
    """

    ret = []
    curr_addr = fuzzerstate.trap_handler_bb_base_addr
    
    # ----------------------------------------------------------
    # Save State
    # ----------------------------------------------------------
    reg_id_context_saver_addr = TRAP_HANDLER_TMP_ID
    reg_id_store_mepc = 1    # use ra to store mepc
    reg_id_imm        = 2    # use sp to store imm
    reg_id_macuse     = 3    # use gp to store mcause
    reg_id_check_comp = 4    # use tp to check compress instr

    # set addr
    lui_imm, addi_imm = li_into_reg(fuzzerstate.reg_context_saver_block_start_addr + 0x80000000, False) 
    ret += [
        # last pickable reg <- addr of reg context saver block
        ImmRdInstruction("lui", reg_id_context_saver_addr, lui_imm,  fuzzerstate.is_design_64bit),
        RegImmInstruction("addi", reg_id_context_saver_addr, reg_id_context_saver_addr, addi_imm, fuzzerstate.is_design_64bit), 
    ]
    curr_addr += 8

    # Clear the top 32 bits, 32bit design no need, because lui will clear the lower 32bit
    if fuzzerstate.is_design_64bit:
        ret += [
            # clear the high 32 bit
            RegImmInstruction("slli", reg_id_context_saver_addr, reg_id_context_saver_addr, 32, fuzzerstate.is_design_64bit),   
            RegImmInstruction("srli", reg_id_context_saver_addr, reg_id_context_saver_addr, 32, fuzzerstate.is_design_64bit),
        ]
        curr_addr += 8

    if fuzzerstate.design_has_fpu:
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            ret.append(FloatStoreInstruction("fsd" if fuzzerstate.is_design_64bit else "fsw", reg_id_context_saver_addr, fp_reg_id, 8*(fp_reg_id+fuzzerstate.num_pickable_regs-1), -1, fuzzerstate.is_design_64bit))
            curr_addr += 4
    for reg_id in range(1, fuzzerstate.num_pickable_regs):
        ret.append(IntStoreInstruction("sd" if fuzzerstate.is_design_64bit else "sw", reg_id_context_saver_addr, reg_id, 8*(reg_id-1), -1, fuzzerstate.is_design_64bit))
        curr_addr += 4

    ret.append(CSRRegInstruction("csrrw", reg_id_macuse, 0, CSR_IDS.MCAUSE))
    curr_addr += 4
    # A terminal fetch fault may leave MEPC unreadable, so dispatch before LHU.
    for cause in (1, 5, 7, 12, 13, 15):
        ret += [
            RegImmInstruction("addi", reg_id_imm, 0, cause, fuzzerstate.is_design_64bit),
            BranchInstruction("bne", reg_id_macuse, reg_id_imm, 8, False, fuzzerstate.is_design_64bit),
        ]
        curr_addr += 8
        ret.append(JALInstruction("jal", 0, fuzzerstate.trap_handler_memory_fault_addr - curr_addr, fuzzerstate.is_design_64bit))
        curr_addr += 4

    # ----------------------------------------------------------
    # mepc <- mepc +4 or +2
    # All the execption are 同步异常, and the high bit of macuse are all 0, in this cause, hardware set mepc to pc
    # ----------------------------------------------------------
    ret += [
        CSRRegInstruction("csrrw", reg_id_store_mepc, 0, CSR_IDS.MEPC),                                          # x1 <- mepc
        IntLoadInstruction("lhu", reg_id_check_comp, reg_id_store_mepc, 0, -1, fuzzerstate.is_design_64bit),     # x4 <- 0(a0)
        RegImmInstruction("andi", reg_id_check_comp, reg_id_check_comp, 0b11, fuzzerstate.is_design_64bit),      # x4 <- x4[1:0], 11 means uncompressed

        # clear x2 first
        RegImmInstruction("addi", reg_id_imm, 0, 0, fuzzerstate.is_design_64bit),                                # x2 <- x0 + 0
        RegImmInstruction("addi", reg_id_imm, 0, 3,  fuzzerstate.is_design_64bit),                               # x2 <- 3
        RegImmInstruction("addi", reg_id_store_mepc, reg_id_store_mepc, 2, fuzzerstate.is_design_64bit),         # x1 = x1 + 2, first add 2 to mepc

        # anti-condition short jump, if uncompressed, add 2 more to mepc
        BranchInstruction("bne", reg_id_check_comp, reg_id_imm, 8, False, fuzzerstate.is_design_64bit),
        RegImmInstruction("addi", reg_id_store_mepc, reg_id_store_mepc, 2, fuzzerstate.is_design_64bit),         # x1 = x1 + 2, add 2 more for uncompressed instr
        CSRRegInstruction("csrrw", 0, reg_id_store_mepc, CSR_IDS.MEPC)                                           # mepc <- x1
    ]
    curr_addr += 36

    # ----------------------------------------------------------
    # We cant directly compare reg with csr, reg_imm store the number, reg_macuse stores the value of macause
    # wether to goto illegal instruction part
    # check if mcause == 2 (illegal instr)
    # ----------------------------------------------------------
    ret += [
        RegImmInstruction("addi",  reg_id_imm, 0, 2,  fuzzerstate.is_design_64bit),   # x2(sp) <- 2
        
        # we can NOT use beq, because imm of beq is 12bits, sometimes smaller than the imm_ill_instr
        # so we use anti-condition short jump
        BranchInstruction("bne", reg_id_macuse, reg_id_imm, 8, False, fuzzerstate.is_design_64bit),
    ]
    curr_addr += 8
    imm_ill_instr = fuzzerstate.trap_handler_ill_instr_bb_base_addr - curr_addr
    ret += [
        JALInstruction("jal", 0, imm_ill_instr, fuzzerstate.is_design_64bit)  # j illegal instr handler
    ]
    curr_addr += 4

    # ----------------------------------------------------------
    # wether to goto ebreak part (now has same addr with ill instr)
    # check if mcause == 3 (ebrak)
    # ----------------------------------------------------------
    ret += [
        RegImmInstruction("addi", reg_id_imm, 0, 3,  fuzzerstate.is_design_64bit),
        BranchInstruction("bne",  reg_id_macuse, reg_id_imm, 8, False, fuzzerstate.is_design_64bit),
    ]
    curr_addr += 8
    imm_ebreak_instr = fuzzerstate.trap_handler_ill_instr_bb_base_addr - curr_addr
    ret += [
        JALInstruction("jal", 0, imm_ebreak_instr, fuzzerstate.is_design_64bit)  # j ebreak handler
    ]
    curr_addr += 4

    # ----------------------------------------------------------
    # wether to goto ecall (M-mode) part (now has same addr with ill instr)
    # check if mcause == 11 (ecall from M-mode)
    # ----------------------------------------------------------    
    ret += [
        RegImmInstruction("addi", reg_id_imm, 0, 11,  fuzzerstate.is_design_64bit),
        BranchInstruction("bne",  reg_id_macuse, reg_id_imm, 8, False, fuzzerstate.is_design_64bit),
    ]

    curr_addr += 8
    imm_ecall_M_instr = fuzzerstate.trap_handler_ill_instr_bb_base_addr - curr_addr
    ret += [
        JALInstruction("jal", 0, imm_ecall_M_instr, fuzzerstate.is_design_64bit)  # j ebreak handler
    ]
    curr_addr += 4

    # ----------------------------------------------------------
    # Catch-all: resume other synchronous exceptions, including misaligned accesses.
    # Jump to the ill_instr handler which restores context and MRETs
    # ----------------------------------------------------------
    imm_catchall = fuzzerstate.trap_handler_ill_instr_bb_base_addr - curr_addr
    ret += [
        JALInstruction("jal", 0, imm_catchall, fuzzerstate.is_design_64bit)
    ]
    curr_addr += 4

    if DO_ASSERT:
        assert len(ret) * 4 <= get_trap_handler_block_size() * 4
    return ret

def trap_handler_ill_instr_block(fuzzerstate: 'FuzzerState'):
    """
    Second level trap handler for ill instr

    """
    ret = []

    # Fisrt restore the context
    reg_id_context_saver_addr = TRAP_HANDLER_TMP_ID
    if fuzzerstate.design_has_fpu:
        for fp_reg_id in range(fuzzerstate.num_pickable_floating_regs):
            ret.append(FloatLoadInstruction("fld" if fuzzerstate.is_design_64bit else "flw", fp_reg_id, reg_id_context_saver_addr, 8*(fp_reg_id+fuzzerstate.num_pickable_regs-1), -1, fuzzerstate.is_design_64bit))

    # keep last pickable reg value
    for reg_id in range(1, fuzzerstate.num_pickable_regs):
        ret.append(IntLoadInstruction("ld" if fuzzerstate.is_design_64bit else "lw", reg_id, reg_id_context_saver_addr, 8*(reg_id-1), -1, fuzzerstate.is_design_64bit))

    # Re-enable VM translation for data accesses before returning
    if fuzzerstate.vm_enabled:
        # Set MPP=M so MRET returns to M-mode and preserves MPRV
        ret += [
            CSRRegInstruction("csrrs", 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
            CSRRegInstruction("csrrs", 0, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
        ]
        # Set MPRV=1 (bit 17) so data accesses use VM after MRET
        ret += [
            RegImmInstruction("addi", TRAP_HANDLER_TMP_ID, 0, 1, fuzzerstate.is_design_64bit),
            RegImmInstruction("slli", TRAP_HANDLER_TMP_ID, TRAP_HANDLER_TMP_ID, 17, fuzzerstate.is_design_64bit),
            CSRRegInstruction("csrrs", 0, TRAP_HANDLER_TMP_ID, CSR_IDS.MSTATUS),
        ]

    ret += [
        PrivilegeDescentInstruction(is_mret=True)     # mret
    ]

    # Terminal memory faults reuse the restore path before returning to the dump.
    fuzzerstate.trap_handler_memory_fault_addr = fuzzerstate.trap_handler_ill_instr_bb_base_addr + len(ret) * 4
    lui_imm, addi_imm = li_into_reg(fuzzerstate.design_base_addr + fuzzerstate.final_bb_base_addr, False)
    ret += [
        ImmRdInstruction("lui", 1, lui_imm, fuzzerstate.is_design_64bit),
        RegImmInstruction("addi", 1, 1, addi_imm, fuzzerstate.is_design_64bit),
    ]
    if fuzzerstate.is_design_64bit:
        ret += [
            RegImmInstruction("slli", 1, 1, 32, fuzzerstate.is_design_64bit),
            RegImmInstruction("srli", 1, 1, 32, fuzzerstate.is_design_64bit),
        ]
    ret.append(CSRRegInstruction("csrrw", 0, 1, CSR_IDS.MEPC))
    ret.append(JALInstruction("jal", 0, -len(ret) * 4, fuzzerstate.is_design_64bit))
    if DO_ASSERT:
        assert len(ret) * 4 <= get_trap_handler_block_size() * 4
    return ret
