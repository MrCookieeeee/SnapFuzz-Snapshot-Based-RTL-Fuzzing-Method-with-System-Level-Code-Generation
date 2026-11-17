import random
import numpy as np
from typing import TYPE_CHECKING

from rv.util import PARAM_REGTYPE, PARAM_SIZES_BITS_32, PARAM_SIZES_BITS_64, INSTR_NEED_PRIME_REG, INSTR_NEED_SAME_RDS
from params.runparams import DO_ASSERT
from params.fuzzparams import NUM_MIN_FREE_INTREGS, REG_FSM_WEIGHTS, NONTAKEN_BRANCH_INTO_RANDOM_DATA_PROBA

from common.utils import IntRegIndivState
from generation.InstructionsCfClass import *

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState


# =====================================================================
# Utility functions
# =====================================================================

def gen_random_imm(instr_str: str, is_design_64bit: bool):
    if DO_ASSERT:
        assert PARAM_REGTYPE[INSTRUCTION_IDS[instr_str]][-1] == ''
    if is_design_64bit:
        imm_width = PARAM_SIZES_BITS_64[INSTRUCTION_IDS[instr_str]][-1]
    else:
        imm_width = PARAM_SIZES_BITS_32[INSTRUCTION_IDS[instr_str]][-1]
    if PARAM_IS_SIGNED[INSTRUCTION_IDS[instr_str]][-1]:
        left_bound  = -(1<<(imm_width-1))
        right_bound = 1<<(imm_width-1)
    else:
        left_bound  = 0
        right_bound = 1<<imm_width

        
    return random.randrange(left_bound, right_bound)

# Random rounding modes
def gen_random_rounding_mode():
    return random.sample([0, 1, 2, 3, 4, 7], 1)[0]

# =====================================================================
# Functions for creation by CFInstructionClass
# Integer instructions
# =====================================================================
def _create_R12DInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in R12DInstructions
    
    # -------------------------------------------------------------------
    # compressed CA-type(c.and, c.xor, c.xor, c.sub) R12D instructions,
    # rs1 == rd
    # -------------------------------------------------------------------
    if instr_str in INSTR_NEED_PRIME_REG:
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        rs2 = fuzzerstate.intregpickstate.pick_int_inputreg_prime()
        rd  = fuzzerstate.intregpickstate.pick_int_outputreg_prime()
        rs1 = rd

    # -------------------------------------------------------------------
    # compressed CR-type(c.mv, c.add) R12D instructions
    # rs1 == rd
    # -------------------------------------------------------------------
    elif instr_str in INSTR_NEED_SAME_RDS:
        if DO_ASSERT: 
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        
        # c.mv needs rds, rs2 != x0
        if instr_str == "c.mv":
            rs2 = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero(False)
            rd  = fuzzerstate.intregpickstate.pick_int_outputreg_nonzero(False) 
        
        # c.add needs rs2 != x0
        elif instr_str == "c.add":
            rs2 = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero(False)
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        else:
            raise ValueError(f"Unexpected instruction string in _create_R12DInstruction: `{instr_str}`")
        rs1 = rd
        
    else:
        rs1, rs2 = tuple(fuzzerstate.intregpickstate.pick_int_inputregs(2))
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    
    return R12DInstruction(instr_str, rd, rs1, rs2, iscompressed)

def _create_ImmRdInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in ImmRdInstructions
    
    rd, imm = None, None
    if instr_str == "c.lui":
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        # c.lui can have rd == 2 or imm == 0
        while rd == None or rd == 2 or imm == 0:
            rd = fuzzerstate.intregpickstate.pick_int_outputreg()
            imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)
    
    # include c.li(no limitations)
    else:
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)

    if instr_str == "auipc" and rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.FREE)
    return ImmRdInstruction(instr_str, rd, imm, fuzzerstate.is_design_64bit, iscompressed)

def _create_RegImmInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in RegImmInstructions

    if instr_str == "c.addi":
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        # c.addi cannot have rd == 0
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_nonzero()
        rs1 = rd
        imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)

    elif instr_str == "c.addi16sp":
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        # c.addi16sp has rds1 = 2
        rd  = fuzzerstate.intregpickstate.pick_int_outputreg_specified(2, authorize_sideeffects=True, force_free_reg=True)
        rs1 = rd
        
        # c.addi16sp imm [-512, 496], imm %16 ==0, excluding 0
        imm = 0
        while imm == 0:
            imm = random.choice(range(-512, 497, 16))

    elif instr_str == "c.addi4spn":
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        
        # c.addi4spn add value to sp, so we have to force set it to FREE after use
        rs1 = fuzzerstate.intregpickstate.pick_int_outputreg_specified(2, authorize_sideeffects=True, force_free_reg=True)
        # c.addi4spn should pick a prime rd
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_prime()

        # c.addi4spn imm [0, 1023], imm %4 ==0 and imm != 0
        imm = random.choice(range(4, 1024, 4))

    elif instr_str == "c.slli":
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        rs1 = rd
        
        imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)

    elif instr_str in ("c.srli", "c.srai", "c.andi"):
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_prime()
        rs1 = rd
        imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)

    else:
        rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()
        imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)

    return RegImmInstruction(instr_str, rd, rs1, imm, fuzzerstate.is_design_64bit, iscompressed)

def _create_BranchInstruction(instr_str: str, fuzzerstate: 'FuzzerState', curr_addr: int, iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in BranchInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    plan_taken = fuzzerstate.curr_branch_taken
    if plan_taken:
        # print('A', flush=True)
        imm = fuzzerstate.next_bb_addr-curr_addr
    else:
        # Select whether to direct toward the random data basic block
        is_random_data_block_in_reach = abs(fuzzerstate.random_data_block_start_addr - curr_addr) < (1<<11) and abs(fuzzerstate.random_data_block_end_addr-4 - curr_addr) < (1<<11)
        if is_random_data_block_in_reach and random.random() < NONTAKEN_BRANCH_INTO_RANDOM_DATA_PROBA:
            lowest_random_data_reachable_addr = max(fuzzerstate.random_data_block_start_addr+4, curr_addr - (1<<11))
            highest_random_data_reachable_addr = min(fuzzerstate.random_data_block_end_addr-4, curr_addr + (1<<11))

            target_addr_in_random_data_block = random.randrange(lowest_random_data_reachable_addr//2, highest_random_data_reachable_addr//2)*2
            imm = target_addr_in_random_data_block-curr_addr
        else:
            imm = gen_random_imm(instr_str, fuzzerstate.is_design_64bit)
    
    # print('New imm', hex(imm), flush=True)
    return BranchInstruction(instr_str, rs1, rs2, imm, plan_taken, fuzzerstate.is_design_64bit, iscompressed)

def _create_JALInstruction(instr_str: str, fuzzerstate: 'FuzzerState', curr_addr: int, iscompressed: bool):

    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    imm = fuzzerstate.next_bb_addr-curr_addr
    
    # c.jal, NOTICE that c.jal only exsist in 32bit machine
    if rd == 1 and -2048 <= imm < 2048 and imm % 2 == 0 and fuzzerstate.is_design_64bit == False:
        iscompressed = True
    
    # c.j
    if rd == 0 and -2048 <= imm < 2048 and imm % 2 == 0:
        iscompressed = True

    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.FREE)

    return JALInstruction(instr_str, rd, imm, fuzzerstate.is_design_64bit, iscompressed), iscompressed

def _create_JALRInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    imm = 0

    # can be compressed to c.jalr
    if rs1 != 0 and rd == 1:
        iscompressed = True

    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if rd > 0:
        fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return JALRInstruction(instr_str, rd, rs1, imm, producer_id, fuzzerstate.is_design_64bit, iscompressed), iscompressed

def _create_SpecialInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return SpecialInstruction(instr_str, rd, rs1, iscompressed)

def _create_SfenceVmaInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return SfenceVmaInstruction(instr_str, rs1, rs2, iscompressed)

def _create_IntLoadInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in IntLoadInstructions

    # c.lw
    if instr_str in INSTR_NEED_PRIME_REG:
        if DO_ASSERT:
            assert iscompressed, f"Instruction `{instr_str}` must be compressed."
        rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state_prime(IntRegIndivState.CONSUMED)
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_prime()

    else:        
        rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
        rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)

    if DO_ASSERT:
        assert producer_id > 0
    return IntLoadInstruction(instr_str, rd, rs1, imm, producer_id, fuzzerstate.is_design_64bit, iscompressed)

def _create_IntStoreInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    """
    Remember, rs1 is for calculate the offset, template: store rs2, offest(rs1)
    """
    if DO_ASSERT:
        assert instr_str in IntStoreInstructions

    # --------------------------------
    # rv32c CI-type c.swsp
    # rd = sp(x2)
    # --------------------------------

    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    rs2 = fuzzerstate.intregpickstate.pick_int_inputreg()
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return IntStoreInstruction(instr_str, rs1, rs2, imm, producer_id, fuzzerstate.is_design_64bit, iscompressed)

# =====================================================================
# Atomic Memory Operations (AMO) and LR/SC
# =====================================================================
def _create_AtomicInstruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in AtomicInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    # LR has no rs2 (hardcoded to 0); AMO and SC pick a source register
    rs2 = 0 if instr_str in ("lr.w", "lr.d") else fuzzerstate.intregpickstate.pick_int_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    aq = random.randint(0, 1)
    rl = random.randint(0, 1)
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return AtomicInstruction(instr_str, rd, rs1, rs2, aq, rl, producer_id, fuzzerstate.is_design_64bit, iscompressed)

# =====================================================================
# Floating-point instructions
# =====================================================================
def _create_FloatLoadInstruction  (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatLoadInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return FloatLoadInstruction(instr_str, frd, rs1, imm, producer_id, fuzzerstate.is_design_64bit, iscompressed)

def _create_FloatStoreInstruction (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatStoreInstructions
    rs1 = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
    frs2 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    imm = 0
    producer_id = fuzzerstate.intregpickstate.get_producer_id(rs1)
    fuzzerstate.intregpickstate.set_regstate(rs1, IntRegIndivState.FREE)
    if DO_ASSERT:
        assert producer_id > 0
    return FloatStoreInstruction(instr_str, rs1, frs2, imm, producer_id, fuzzerstate.is_design_64bit, iscompressed)

def _create_FloatToIntInstruction (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatToIntInstructions
    rm = gen_random_rounding_mode()
    frs1 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    return FloatToIntInstruction(instr_str, rd, frs1, rm, iscompressed)

def _create_IntToFloatInstruction (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in IntToFloatInstructions
    rm = gen_random_rounding_mode()
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return IntToFloatInstruction(instr_str, frd, rs1, rm, iscompressed)

def _create_Float4Instruction     (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float4Instructions
    rm = gen_random_rounding_mode()
    frs1, frs2, frs3 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(3))
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float4Instruction(instr_str, frd, frs1, frs2, frs3, rm, iscompressed)

def _create_Float3Instruction     (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float3Instructions
    rm = gen_random_rounding_mode()
    frs1, frs2 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(2))
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float3Instruction(instr_str, frd, frs1, frs2, rm, iscompressed)

def _create_Float3NoRmInstruction (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float3NoRmInstructions
    frs1, frs2 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(2))
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float3NoRmInstruction(instr_str, frd, frs1, frs2, iscompressed)

def _create_Float2Instruction     (instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in Float2Instructions
    rm = gen_random_rounding_mode()
    frs1 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    return Float2Instruction(instr_str, frd, frs1, rm, iscompressed)

def _create_FloatIntRd2Instruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatIntRd2Instructions
    frs1, frs2 = tuple(fuzzerstate.floatregpickstate.pick_float_inputregs(2))
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    return FloatIntRd2Instruction(instr_str, rd, frs1, frs2, iscompressed)

def _create_FloatIntRd1Instruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatIntRd1Instructions
    frs1 = fuzzerstate.floatregpickstate.pick_float_inputreg()
    rd = fuzzerstate.intregpickstate.pick_int_outputreg()
    return FloatIntRd1Instruction(instr_str, rd, frs1, iscompressed)

def _create_FloatIntRs1Instruction(instr_str: str, fuzzerstate: 'FuzzerState', iscompressed: bool):
    if DO_ASSERT:
        assert instr_str in FloatIntRs1Instructions
    frd = fuzzerstate.floatregpickstate.pick_float_outputreg()
    rs1 = fuzzerstate.intregpickstate.pick_int_inputreg()
    return FloatIntRs1Instruction(instr_str, frd, rs1, iscompressed)

# =====================================================================
# Exposed function
# =====================================================================
def create_regfsm_instrobjs(fuzzerstate: 'FuzzerState'):
    # Check which reg fsm operations are doable
    doable_fsm_ops = np.zeros(3, dtype=np.int8)
    doable_fsm_ops[0] = fuzzerstate.intregpickstate.get_num_regs_in_state(IntRegIndivState.FREE) > NUM_MIN_FREE_INTREGS
    doable_fsm_ops[1] = fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PRODUCED0)
    doable_fsm_ops[2] = fuzzerstate.intregpickstate.exists_reg_in_state(IntRegIndivState.PRODUCED1)

    effective_weights = doable_fsm_ops * REG_FSM_WEIGHTS

    choice = None
    while choice is None or not doable_fsm_ops[choice]:
        choice = random.choices(range(3), effective_weights, k=1)[0]

    if choice == 0: # FREE -> PRODUCED0
        return create_targeted_producer0_instrobj(fuzzerstate)
    elif choice == 1: # PRODUCED0 -> PRODUCED1
        return create_targeted_producer1_instrobj(fuzzerstate)
    elif choice == 2: # PRODUCED1 -> FREE/CONSUMED
        return create_targeted_consumer_instrobj(fuzzerstate)
    else:
        raise ValueError(f"Unexpected choice: `{choice}`.")
    
def create_targeted_producer0_instrobj(fuzzerstate: 'FuzzerState', need_prime: bool = False):
    """
    Find a FREE reg, write something in it, and set its state to PRODUCED0
    FREE -> PRODUCED0

    Args:
        need_prime: whether we need to pick a prime reg, for compress instr
    """
    fuzzerstate.next_producer_id += 1
    # find a reg
    if need_prime:
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_prime()
    else:
        rd = fuzzerstate.intregpickstate.pick_int_outputreg_nonzero(False)

    fuzzerstate.intregpickstate.set_producer_id(rd, fuzzerstate.next_producer_id)
    fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.PRODUCED0)
    return [PlaceholderProducerInstr0(rd, fuzzerstate.next_producer_id, fuzzerstate.is_design_64bit)]

def create_targeted_producer1_instrobj(fuzzerstate: 'FuzzerState', need_prime: bool = False):
    """
    Find a PRODUCED0 reg, update its value again, and set its state to PRODUCED1
    PRODUCED0 -> PRODUCED1
    """
    if need_prime:
        rd = fuzzerstate.intregpickstate.pick_int_reg_in_state_prime(IntRegIndivState.PRODUCED0)
    else:
        rd = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PRODUCED0)
    # fuzzerstate.intregpickstate.set_producer1_location(rd, len(fuzzerstate.instr_objs_seq), len(fuzzerstate.instr_objs_seq[0])) # Optimization currently unused
    fuzzerstate.intregpickstate.set_regstate(rd, IntRegIndivState.PRODUCED1)
    return [PlaceholderProducerInstr1(rd, fuzzerstate.intregpickstate.get_producer_id(rd), fuzzerstate.is_design_64bit)]

def create_targeted_consumer_instrobj(fuzzerstate: 'FuzzerState', need_prime: bool = False):
    """
    Find a PRODUCED1 reg, consume it, and set its state to CONSUMED (or FREE if 32-bit design)
    PRODUCED1 -> CONSUMED
    """
    rdep = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero(False) # We want to create dependencies, therefore we choose not to accept x0
    
    if need_prime:
        rprod = fuzzerstate.intregpickstate.pick_int_reg_in_state_prime(IntRegIndivState.PRODUCED1)
    else:
        rprod = fuzzerstate.intregpickstate.pick_int_reg_in_state(IntRegIndivState.PRODUCED1)
    
    # WARNING: We CANNOT throw a PRODUCEDX into the nature because its value will change between spike and RTL.
    rd = rprod
    fuzzerstate.intregpickstate.set_regstate(rprod, IntRegIndivState.CONSUMED)
    
    # -----------------------------------------------------------------
    # For 32bit design, we just consume the PRODUCED1 reg
    # For 64bit, however, we MUST first mask it to 32bit, then consume it
    # So a 64bit consume instr include and + and + xor
    # -----------------------------------------------------------------
    if fuzzerstate.is_design_64bit:
        return [PlaceholderPreConsumerInstr(rprod), PlaceholderPreConsumerInstr(rdep), PlaceholderConsumerInstr(rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))]
    else:
        return [PlaceholderConsumerInstr(rd, rdep, rprod, fuzzerstate.intregpickstate.get_producer_id(rprod))]


def create_instr(instr_str: str, fuzzerstate: 'FuzzerState', curr_addr: int, iscompressed: bool = False):
    """
    The reservation in the MemoryView is already done ahead and should not be reiterated here.
    
    Return:
        jalr_addr_reg: only meaningful if a jalr is present (in the latter case, it should be the next instruction)
    """
    # Integer instructions
    if instr_str in R12DInstructions:
        return _create_R12DInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in ImmRdInstructions:
        return _create_ImmRdInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in RegImmInstructions:
        return _create_RegImmInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in BranchInstructions:
        return _create_BranchInstruction(instr_str, fuzzerstate, curr_addr, iscompressed)
    
    # Has different return value
    elif instr_str in JALInstructions:
        return _create_JALInstruction(instr_str, fuzzerstate, curr_addr, iscompressed)
    elif instr_str in JALRInstructions:
        return _create_JALRInstruction(instr_str, fuzzerstate, iscompressed)
    
    # Special instrs
    elif instr_str in SpecialInstructions:
        return _create_SpecialInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in SfenceVmaInstructions:
        return _create_SfenceVmaInstruction(instr_str, fuzzerstate, iscompressed)

    elif instr_str in IntLoadInstructions:
        return _create_IntLoadInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in IntStoreInstructions:
        return _create_IntStoreInstruction(instr_str, fuzzerstate, iscompressed)
    
    # Atomic Memory Operations
    elif instr_str in AtomicInstructions:
        return _create_AtomicInstruction(instr_str, fuzzerstate, iscompressed)
    
    # Floating point instructions
    elif instr_str in FloatLoadInstructions:
        return _create_FloatLoadInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatStoreInstructions:
        return _create_FloatStoreInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatToIntInstructions:
        return _create_FloatToIntInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in IntToFloatInstructions:
        return _create_IntToFloatInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float4Instructions:
        return _create_Float4Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float3Instructions:
        return _create_Float3Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float3NoRmInstructions:
        return _create_Float3NoRmInstruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in Float2Instructions:
        return _create_Float2Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatIntRd2Instructions:
        return _create_FloatIntRd2Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatIntRd1Instructions:
        return _create_FloatIntRd1Instruction(instr_str, fuzzerstate, iscompressed)
    elif instr_str in FloatIntRs1Instructions:
        return _create_FloatIntRs1Instruction(instr_str, fuzzerstate, iscompressed)

    else:
        raise ValueError(f"Unexpected instruction string: `{instr_str}`")
