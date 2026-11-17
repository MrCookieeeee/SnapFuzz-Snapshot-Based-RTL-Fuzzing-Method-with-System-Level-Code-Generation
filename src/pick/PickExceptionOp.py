import copy
import enum
import random
from typing import TYPE_CHECKING

from params.runparams import DO_ASSERT
from common.Spike import SPIKE_MEDELEG_MASK
from rv.csrids import CSR_IDS, INTERESTING_CSRS_INACCESSIBLE_FROM_SUPERVISOR, INTERESTING_CSRS_INACCESSIBLE_FROM_USER
from params.fuzzparams import MPP_BOTH_ENDIS_REGISTER_ID, MPP_TOP_ENDIS_REGISTER_ID, SPP_ENDIS_REGISTER_ID, MAX_NUM_PICKABLE_FLOATING_REGS, MAX_NUM_PICKABLE_REGS, SIMPLE_ILLEGAL_INSTRUCTION_PROBA, PROBA_PICK_WRONG_FPU, TRAP_HANDLER_TMP_ID
from generation.InstructionsCfClass import Float3Instructions

from common.utils import gen_random_rounding_mode, li_into_reg
from common.TolerateBugs import is_tolerate_rocket_minstret

from initialstate.PrivilegeState import PrivilegeStateEnum
from generation.InstructionsCfClass import CSRRegInstruction, SimpleExceptionEncapsulator, JALInstruction, Float3Instruction, SimpleIllegalInstruction, PrivilegeDescentInstruction, EcallEbreakInstruction, MisalignedMemInstruction, GenericCSRWriterInstruction, TvecWriterInstruction, EPCWriterInstruction, ImmRdInstruction, RegImmInstruction, IntLoadInstruction, IntStoreInstruction
from common.utils import ExceptionCauseVal
from common.utils import IntRegIndivState

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState

# Also used by the medeleg CSR
EXCEPTION_INSTR_INITIAL_BOOSTERS = {
    ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:        0,
    ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:           0, # 4,
    ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:          1,
    ExceptionCauseVal.ID_BREAKPOINT:                   0.1,
    ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:         0.1,
    ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:            0.05, # 2,
    ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:    0.1,
    ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:       0.05, # 2,
    ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE: 0.1,
    ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE: 0,
    ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE: 0.1,
    ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT:       0, # 4,
    ExceptionCauseVal.ID_LOAD_PAGE_FAULT:              0.05, # 2,
    ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:         0.05  # 2
}




# @brief this function generates an instruction that will fill the xPP field of mstatus with the provided value.
# @return a CFInstructionType that will fill the xPP field of mstatus with the provided value.
def gen_ppfill_instrs(fuzzerstate: 'FuzzerState'):
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE, "The function gen_ppfill_instrs should only be called in machine mode. Currently in " + str(fuzzerstate.privilegestate.privstate)

    # Technically, spp can be written even if supervisor mode does not exist. But leave this detail for the FUTURE.
    if fuzzerstate.design_has_supervisor_mode:
        is_mpp = random.random() < 0.5
    else:
        is_mpp = True

    # Ignore the return value of mstatus for now
    rd = 0

    # Choose the target. It should be a valid target.
    if is_mpp:
        if not fuzzerstate.design_has_supervisor_mode and not fuzzerstate.design_has_user_mode:
            target_privlvl = PrivilegeStateEnum.MACHINE
        elif fuzzerstate.design_has_supervisor_mode and not fuzzerstate.design_has_user_mode:
            target_privlvl = random.choice([PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE])
        elif not fuzzerstate.design_has_supervisor_mode and fuzzerstate.design_has_user_mode:
            target_privlvl = random.choice([PrivilegeStateEnum.USER, PrivilegeStateEnum.MACHINE])
        else:
            target_privlvl = random.choice([PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR, PrivilegeStateEnum.MACHINE])
    else:
        if fuzzerstate.design_has_user_mode:
            target_privlvl = random.choice([PrivilegeStateEnum.USER, PrivilegeStateEnum.SUPERVISOR])
        else:
            target_privlvl = PrivilegeStateEnum.SUPERVISOR

    if is_mpp:
        if target_privlvl == PrivilegeStateEnum.USER:
            ret = [CSRRegInstruction("csrrc", rd, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
        elif target_privlvl == PrivilegeStateEnum.SUPERVISOR:
            # Could theretically be done in a single instruction if we had one more mask register.
            ret = [CSRRegInstruction("csrrs", rd, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS), CSRRegInstruction("csrrc", rd, MPP_TOP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
        elif target_privlvl == PrivilegeStateEnum.MACHINE:
            ret = [CSRRegInstruction("csrrs", rd, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
        else:
            raise NotImplementedError("Hypervisor mode not implemented")
    else:
        if target_privlvl == PrivilegeStateEnum.USER:
            ret = [CSRRegInstruction("csrrc", rd, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
                CSRRegInstruction("csrrc", rd, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
        elif target_privlvl == PrivilegeStateEnum.SUPERVISOR:
            ret = [CSRRegInstruction("csrrs", rd, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
                CSRRegInstruction("csrrs", rd, SPP_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
        else:
            raise Exception("Invalid target privlvl when setting spp")

    # Update the mpp/spp in our bookkeeping
    if is_mpp:
        fuzzerstate.privilegestate.curr_mstatus_mpp = target_privlvl
    else:
        fuzzerstate.privilegestate.curr_mstatus_spp = target_privlvl

    return ret



def pick_illegal_instruction(is_mtvec, fuzzerstate: 'FuzzerState', old_privilege):
    """
    Illegal instructions includes: 1.Simple non-existing instruction. 2.Form an illegal CSR access.
    
    Warning: the privilege state of fuzzerstate is already updated!!
    
    Args:
        old_privilege the privilege state before the exception
    """

    # -----------------------------------------------------------------------
    # Case 1: just a simple illegal instr
    # -----------------------------------------------------------------------
    if SIMPLE_ILLEGAL_INSTRUCTION_PROBA < random.random():
        return SimpleIllegalInstruction(is_mtvec)

    # -----------------------------------------------------------------------
    # Case 2: Use FPU when is not activated, but NOT in use right now TODO
    # -----------------------------------------------------------------------
    if not fuzzerstate.design_has_fpu or not fuzzerstate.is_fpu_activated:
        if random.random() < PROBA_PICK_WRONG_FPU * 0.01**fuzzerstate.design_has_fpu:
            rm = gen_random_rounding_mode()
            frs1, frs2 = random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS), random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS)
            frd = random.randrange(MAX_NUM_PICKABLE_FLOATING_REGS)
            return SimpleExceptionEncapsulator(is_mtvec, None, Float3Instruction(random.choice(Float3Instructions), frd, frs1, frs2, rm, False))

    # -----------------------------------------------------------------------
    # Case 3: According to recent mode, choose a can't accessed reg
    # -----------------------------------------------------------------------
    if old_privilege == PrivilegeStateEnum.MACHINE:
        candidate_instructions = [
            SimpleExceptionEncapsulator(is_mtvec, None, SimpleIllegalInstruction(is_mtvec)),
            SimpleExceptionEncapsulator(is_mtvec, None, CSRRegInstruction("csrrw", random.randrange(fuzzerstate.num_pickable_regs), random.randrange(fuzzerstate.num_pickable_regs), 0xCCA))
        ]
    elif old_privilege == PrivilegeStateEnum.SUPERVISOR:
        candidate_instructions = [
            SimpleExceptionEncapsulator(is_mtvec, None, PrivilegeDescentInstruction(True)),
            SimpleExceptionEncapsulator(is_mtvec, None, CSRRegInstruction("csrrw", random.randrange(fuzzerstate.num_pickable_regs), random.randrange(fuzzerstate.num_pickable_regs), random.choice(INTERESTING_CSRS_INACCESSIBLE_FROM_SUPERVISOR))),
        ]
    elif old_privilege == PrivilegeStateEnum.USER:
        candidate_instructions = [
            SimpleExceptionEncapsulator(is_mtvec, None, random.choice([PrivilegeDescentInstruction(True), PrivilegeDescentInstruction(False)])),
            SimpleExceptionEncapsulator(is_mtvec, None, CSRRegInstruction("csrrw", random.randrange(fuzzerstate.num_pickable_regs), random.randrange(fuzzerstate.num_pickable_regs), random.choice(INTERESTING_CSRS_INACCESSIBLE_FROM_USER))),
        ]
    else:
        raise Exception("Unknown privilege state: " + str(old_privilege))
    ret = random.choice(candidate_instructions)
    return ret

def _gen_memory_exception_instrs(fuzzerstate: 'FuzzerState', cause):
    is_load = cause in (ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED,
                        ExceptionCauseVal.ID_LOAD_ACCESS_FAULT,
                        ExceptionCauseVal.ID_LOAD_PAGE_FAULT)
    is_misaligned = cause in (ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED,
                              ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED)
    is_page_fault = cause in (ExceptionCauseVal.ID_LOAD_PAGE_FAULT,
                              ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT)
    ret = []
    base_reg = 0
    suffix = 'w'
    if is_misaligned:
        widths = ((2, 'h'), (4, 'w'))
        if fuzzerstate.is_design_64bit:
            widths += ((8, 'd'),)
        width, suffix = random.choice(widths)
        address = random.choice([
            address for address in range(fuzzerstate.random_data_block_start_addr,
                                         fuzzerstate.random_data_block_end_addr - width + 1)
            if address % width
        ]) + fuzzerstate.design_base_addr
        lui_imm, addi_imm = li_into_reg(address, False)
        base_reg = TRAP_HANDLER_TMP_ID
        ret = [
            CSRRegInstruction('csrrs', 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
            ImmRdInstruction('lui', base_reg, lui_imm, fuzzerstate.is_design_64bit),
            RegImmInstruction('addi', base_reg, base_reg, addi_imm, fuzzerstate.is_design_64bit),
        ]
        if fuzzerstate.is_design_64bit:
            ret += [RegImmInstruction('slli', base_reg, base_reg, 32, True),
                    RegImmInstruction('srli', base_reg, base_reg, 32, True)]
    elif is_page_fault:
        ret = [
            ImmRdInstruction('lui', TRAP_HANDLER_TMP_ID, 0x20, fuzzerstate.is_design_64bit),
            CSRRegInstruction('csrrs', 0, TRAP_HANDLER_TMP_ID, CSR_IDS.MSTATUS),
            CSRRegInstruction('csrrc', 0, MPP_BOTH_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS),
        ]
    if is_load:
        instr = IntLoadInstruction('l' + suffix, 0, base_reg, 0, -1, fuzzerstate.is_design_64bit)
    else:
        instr = IntStoreInstruction('s' + suffix, base_reg, 0, 0, -1, fuzzerstate.is_design_64bit)
    fault = SimpleExceptionEncapsulator(True, None, instr)
    fault.exception_cause = cause
    fault.terminal_exception = not is_misaligned
    return ret + [fault]


def gen_next_exception_instr_from_instr_illegal_type(fuzzerstate: 'FuzzerState', curr_addr):
    """
    SnapFuzz first allocates a random trap-handler space and directs exceptions to that address.
    Moreover, after trap into the handler, there are two options: 1. pc <- mepc and continue execute
                                                                  2. go to final block and dump reg
    In situation 1, we can generate another(or more) execptions
    
    """

    exception_instr_type = _gen_next_exception_instr_type(fuzzerstate)

    ret = []

    # Check for delegations
    # When doing boom and rocket, is_mtvec is always true
    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        is_mtvec = True
    else:
        if DO_ASSERT:
            assert fuzzerstate.privilegestate.medeleg_val is not None
        # check wether the exact bit of medeleg_val is 1 (1 means can be delegate)
        is_mtvec = not (fuzzerstate.privilegestate.medeleg_val & (1 << exception_instr_type.value))

    # handle mepc/sepc and updates xpp
    # if is_mtvec:
    #     fuzzerstate.privilegestate.is_mepc_populated = False
    #     fuzzerstate.privilegestate.curr_mstatus_mpp = fuzzerstate.privilegestate.privstate
    # else:
    #     fuzzerstate.privilegestate.is_sepc_populated = False
    #     fuzzerstate.privilegestate.curr_mstatus_spp = fuzzerstate.privilegestate.privstate

    # if is_mtvec:
    #     fuzzerstate.privilegestate.is_mtvec_populated = False
    # else:
    #     fuzzerstate.privilegestate.is_stvec_populated = False

    # Update the privilege state
    old_privilege = fuzzerstate.privilegestate.privstate
    if is_mtvec:
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.MACHINE
    else:
        fuzzerstate.privilegestate.privstate = PrivilegeStateEnum.SUPERVISOR

    if exception_instr_type in (ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED,
                               ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED,
                               ExceptionCauseVal.ID_LOAD_ACCESS_FAULT,
                               ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT,
                               ExceptionCauseVal.ID_LOAD_PAGE_FAULT,
                               ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT) \
            and fuzzerstate.design_name in ('rocket', 'boom'):
        assert old_privilege == PrivilegeStateEnum.MACHINE and is_mtvec
        return _gen_memory_exception_instrs(fuzzerstate, exception_instr_type)
    
    # -------------------------------------------------------------------- 
    # Illegal instr contains simple ill instr, or access wrong/no-exsist reg
    # -------------------------------------------------------------------- 
    if exception_instr_type == ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:
        return [pick_illegal_instruction(is_mtvec, fuzzerstate, old_privilege)]
    
    # -------------------------------------------------------------------- 
    # ebreak
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_BREAKPOINT:
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return [SimpleExceptionEncapsulator(is_mtvec, None, EcallEbreakInstruction("ebreak"))]
    

    # -------------------------------------------------------------------- 
    # M-mode ecall
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE:
        if DO_ASSERT:
            assert old_privilege == PrivilegeStateEnum.MACHINE
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return [SimpleExceptionEncapsulator(is_mtvec, None, EcallEbreakInstruction("ecall"))]
    
    # -------------------------------------------------------------------- 
    # U-mode ecall
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE:
        if DO_ASSERT:
            assert old_privilege == PrivilegeStateEnum.USER
            assert 0
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return [SimpleExceptionEncapsulator(is_mtvec, None, EcallEbreakInstruction("ecall"))]
    
    # -------------------------------------------------------------------- 
    # S-mode ecall
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE:
        if DO_ASSERT:
            assert old_privilege == PrivilegeStateEnum.SUPERVISOR
            assert 0
        fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = ('rocket' in fuzzerstate.design_name and not is_tolerate_rocket_minstret()) # rocket has minstret inaccurate because of ecall/ebreak
        return [SimpleExceptionEncapsulator(is_mtvec, None, EcallEbreakInstruction("ecall"))]

    # -------------------------------------------------------------------- 
    # Not supported
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT:
        raise NotImplementedError("ID_INSTRUCTION_PAGE_FAULT not yet supported")
    
    elif exception_instr_type == ExceptionCauseVal.ID_LOAD_PAGE_FAULT:
        raise NotImplementedError("ID_LOAD_PAGE_FAULT not yet supported")
    
    elif exception_instr_type == ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:
        raise NotImplementedError("ID_STORE_AMO_PAGE_FAULT not yet supported")
    
    elif exception_instr_type == ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:
        raise NotImplementedError("ID_INSTR_ACCESS_FAULT not yet supported")

    elif exception_instr_type == ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:
        raise [NotImplementedError("ID_STORE_AMO_ACCESS_FAULT not yet supported")]
    
    elif exception_instr_type == ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:
        raise NotImplementedError("ID_LOAD_ACCESS_FAULT not yet supported")
    
    # -------------------------------------------------------------------- 
    # Not activated
    # load addr misaligned, no designs support, 
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:
        if DO_ASSERT:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.CONSUMED)
            assert 0
        return [MisalignedMemInstruction(is_mtvec, fuzzerstate, True)]
    
    # -------------------------------------------------------------------- 
    # Not activated
    # Unfortunately, ALL tested designs dont support misaligned access
    # So it's useless right now
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:
        if DO_ASSERT:
            assert not fuzzerstate.design_has_compressed_support, "Compressed instructions are supported, so no instruction address misalignment can occur."
        # The instruction misalignment will always be 2 bytes, because CF instructions have a granularity of 2 bytes.
        # Select the address to load. We care about blacklisting, in the (erroneous) case where the data would have some influence.
        misaligned_tgt_addr = random.randrange(0, (fuzzerstate.memview_blacklist.memsize-1) // 4) * 4 + 2 # -1 because we dont want to have an access fault but an instruction misaligned fault here.
        if DO_ASSERT:
            assert misaligned_tgt_addr % 4 == 2
            assert misaligned_tgt_addr >= 0
            assert misaligned_tgt_addr + 4 < fuzzerstate.memview_blacklist.memsize
            assert 0
        # Find out the address of the instruction to be created, to make the relative jump
        jal_addr = fuzzerstate.bb_start_addr_seq[-1] + 4*len(fuzzerstate.instr_objs_seq) # NO_COMPRESSED
        return SimpleExceptionEncapsulator(is_mtvec, None, JALInstruction("jal", 0, misaligned_tgt_addr - jal_addr))
        
    # -------------------------------------------------------------------- 
    # Store AMO addr misaligned, no designs support
    # -------------------------------------------------------------------- 
    elif exception_instr_type == ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:
        if DO_ASSERT:
            assert fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.CONSUMED)
            assert 0
        return [MisalignedMemInstruction(is_mtvec, fuzzerstate, False)]
    
    else:
        assert 0, "generate non-exsist execption type"


def _get_exceptionoptype_filtered_weights(fuzzerstate: 'FuzzerState'):
    """
    For now, the weights used for choosing instructions are fixed over time.
    This function filters the exceptionoptype weights according to the capabilities of a given CPU
    
    Return:
        normalized dict of ExceptionCauseVals that can currently be used.
    # """
    takable_exceptions = fuzzerstate.privilegestate.gen_takable_exception_dict(fuzzerstate)
    ret_dict = {
        exception_type: int(takable_exceptions[exception_type]) * fuzzerstate.exception_instr_pickweights[exception_type]
        for exception_type in fuzzerstate.exception_instr_pickweights
    }
    # Normalize the weights
    if DO_ASSERT:
        assert sum(ret_dict.values()) > 0, "The sum of filtered exceptionop pick weights must be strictly positive! Currently: " + str(sum(ret_dict.values()))
    norm_factor = 1/sum(ret_dict.values())
    for curr_key in ret_dict:
        ret_dict[curr_key] = ret_dict[curr_key] * norm_factor
    return ret_dict


def _gen_next_exception_instr_type(fuzzerstate) -> ExceptionCauseVal:
    """
    weights: a list either None (equal weights) or as long as ExceptionCauseVal
    
    Return:
        an ExceptionCauseVal
    """
    # Depending on delegations and whether mtvec and stvec are populated, select which exceptions are possible
    weights = copy.copy(_get_exceptionoptype_filtered_weights(fuzzerstate))
    if DO_ASSERT:
        assert sum(weights.values()) > 0, "The sum of filtered exceptionop pick weights must be strictly positive! Currently: " + str(sum(weights.values()))

    # Sample causes and weights in the same dictionary order.
    return random.choices(list(weights), weights=list(weights.values()))[0]

def gen_medeleg_instr(fuzzerstate: 'FuzzerState'):
    """
    Generates an instruction that will fill medeleg with the provided value.

    Return:
        a CFInstructionType that will fill the tvec with the provided value.
    """
    from common.ProfileDesign import get_medeleg_mask
    
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE

    # The value written to Spike’s MEDELEG, but masked so it only includes bits that Spike supports
    val_to_write_spike = 0

    # The value written to DUT’s MEDELEG register, including illegal bits
    val_to_write_cpu   = 0

    # Generation-only uses the Spike mask; RTL testing uses the profiled DUT mask.
    supported_medeleg_bits = getattr(fuzzerstate, "medeleg_mask", None)
    if supported_medeleg_bits is None:
        supported_medeleg_bits = get_medeleg_mask(fuzzerstate.design_name)
    supported_medeleg_bits &= SPIKE_MEDELEG_MASK

    # Convert supported_medeleg_bits to array of bits for easier processing
    supported_medeleg_bits_arr = []
    while supported_medeleg_bits:
        supported_medeleg_bits_arr.append(supported_medeleg_bits & 1)
        supported_medeleg_bits >>= 1
    del supported_medeleg_bits

    for bit_id, bit_val in enumerate(supported_medeleg_bits_arr):
        # TODO
        # The line below is a cool idea but makes the analysis more difficult, so we don't do it for now and we AND with bit_val
        # random_bit = random.randint(0, 1) 
        # Reason: some times cpu wrongly write 1 to unsupported meledge bits
        # So, we want to do: If the bit is not supported by the CPU, set it to 0 for Spike, but set it randomly for the CPU
        # But now right now is not supported ~

        # right now we make sure if the delegation bit is not supported, both Spike and CPU get 0
        random_bit = bit_val and random.randint(0, 1)
        val_to_write_cpu |= random_bit << bit_id

        if bit_val == 1:
            val_to_write_spike |= random_bit << bit_id

    # Get some consumed register
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)

    if fuzzerstate.privilegestate.medeleg_val is None:
        rd = 0 # The reset value of medeleg differ between spike and the CPU. # FUTURE we can get any and call it POLLUTED
    else:
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()

    # Update the delegated state in our model
    fuzzerstate.privilegestate.medeleg_val = val_to_write_spike

    return GenericCSRWriterInstruction(CSR_IDS.MEDELEG, rd, rs1, producer_id, val_to_write_spike, val_to_write_cpu)


def gen_tvecfill_instr(fuzzerstate: 'FuzzerState'):

    can_populate_mtvec = fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and not fuzzerstate.privilegestate.is_mtvec_populated
    can_populate_stvec = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR) or \
                            (fuzzerstate.design_has_supervisor_mode and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE)) \
                            and not fuzzerstate.privilegestate.is_stvec_populated

    if DO_ASSERT:
        assert can_populate_mtvec or can_populate_stvec

    is_mtvec = True # If True, then mtvec, else stvec

    # Choose between mtvec and stvec
    if can_populate_mtvec:
        if can_populate_stvec:
            is_mtvec = random.random() < 0.5
        else:
            is_mtvec = True
    else:
        is_mtvec = False

    # Get some consumed register
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)

    # If this is the first write to the reg, then the reset val should be ignored
    if is_mtvec:
        if fuzzerstate.privilegestate.is_mtvec_still_reset_val:
            fuzzerstate.privilegestate.is_mtvec_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_mtvec_populated = True
    else:
        if fuzzerstate.privilegestate.is_stvec_still_reset_val:
            fuzzerstate.privilegestate.is_stvec_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_stvec_populated = True

    return TvecWriterInstruction(is_mtvec, rd, rs1, producer_id)

# @brief this function generates an instruction that will fill the epc with the provided value.
# @return a CFInstructionType that will fill the epc with the provided value.
def gen_epcfill_instr(fuzzerstate: 'FuzzerState'):
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate != PrivilegeStateEnum.USER

    can_populate_mepc = fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE and not fuzzerstate.privilegestate.is_mepc_populated
    can_populate_sepc = ((fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.SUPERVISOR) or \
                            (fuzzerstate.design_has_supervisor_mode and fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE)) \
                            and not fuzzerstate.privilegestate.is_sepc_populated

    if DO_ASSERT:
        assert can_populate_mepc or can_populate_sepc

    is_mepc = True # If True, then mepc, else sepc

    # Choose between mepc and sepc
    if can_populate_mepc:
        if can_populate_sepc:
            is_mepc = random.random() < 0.5
        else:
            is_mepc = True
    else:
        is_mepc = False

    # Get some consumed register
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)

    # If this is the first write to the reg, then the reset val should be ignored
    if is_mepc:
        if fuzzerstate.privilegestate.is_mepc_still_reset_val:
            fuzzerstate.privilegestate.is_mepc_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_mepc_populated = True
    else:
        if fuzzerstate.privilegestate.is_sepc_still_reset_val:
            fuzzerstate.privilegestate.is_sepc_still_reset_val = False
            rd = 0
        else:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        fuzzerstate.privilegestate.is_sepc_populated = True

    return EPCWriterInstruction(is_mepc, rd, rs1, producer_id)

