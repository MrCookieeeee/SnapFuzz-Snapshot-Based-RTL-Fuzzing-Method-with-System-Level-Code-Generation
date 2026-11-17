import random
from typing import TYPE_CHECKING

from params.runparams import DO_ASSERT
from common.Spike import SPIKE_STARTADDR
from params.fuzzparams import RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES, BASIC_BLOCK_MIN_SPACE, LIMIT_MEM_SATURATION_RATIO, BRANCH_TAKEN_PROBA, MAX_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_FLOATING_REGS, INITIAL_BLOCK_MAX_SIZE_BYTES, PAGE_TABLE_SIZE_2LEVEL, PAGE_TABLE_SIZE_3LEVEL, PROBA_STOP_ON_EXCEPTION
from generation.Instructions import INSTRUCTIONS_BY_ISA_CLASS

from generation.GenInitialBlock import gen_initial_basic_block
from generation.GenFinalBlock import get_finalblock_max_size, finalblock, pop_last_bbs_to_connect_with_final_block
from generation.GenTrapHandlerBlocks import get_trap_handler_block_size, trap_handler_block, trap_handler_ill_instr_block
from generation.Instructions import get_range_bits_per_instrclass, gen_next_isainstrclass
from generation.InstructionsCfClass import is_placeholder
from generation.GenProducerID import gen_producer_id_to_tgtaddr

from pick.CreateInstr import create_regfsm_instrobjs
from pick.PickFpuOp import gen_fpufsm_instrs
from pick.PickPrivDescentOp import gen_priv_descent_instr
from pick.PickExceptionOp import gen_ppfill_instrs, gen_medeleg_instr, gen_tvecfill_instr, gen_epcfill_instr, gen_next_exception_instr_from_instr_illegal_type
from pick.PickInstrType import gen_next_instrstr_from_isaclass
from pick.PickRandomCSR import gen_random_csr_op
from pick.CreateInstr import create_instr
from pick.PickMemOp import pick_memop_addr, is_instrstr_load, get_alignment_bits

from generation.Instructions import ISAInstrClass
from generation.InstructionsCfClass import BranchInstruction, PlaceholderProducerInstr0, PlaceholderProducerInstr1, PlaceholderConsumerInstr, JALInstruction, SfenceVmaInstruction
from common.utils import IntRegIndivState
from initialstate.FuzzerState import FuzzerState
from initialstate.PrivilegeState import PrivilegeStateEnum


if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState


def gen_next_bb_addr(fuzzerstate: 'FuzzerState', isa_class: ISAInstrClass, curr_addr: int):
    """
    Given the provided control flow instruction, finds a location for a new block, but does not allocate it.

    Returns:
        False if could not find a next bb address
    """

    range_bits_each_direction = get_range_bits_per_instrclass(isa_class)
    # We must select the next basic block address before the resolution
    fuzzerstate.next_bb_addr = fuzzerstate.memview.gen_random_free_addr(4, BASIC_BLOCK_MIN_SPACE, curr_addr - (1 << range_bits_each_direction), curr_addr + (1 << range_bits_each_direction))
    # If we could not find a new address where to place the next basic block, then return and consider this stage complete.
    if fuzzerstate.next_bb_addr is None:
        return False
    return True

def gen_basicblock(fuzzerstate: 'FuzzerState'):
    """
    Generate a privileged descent instruction or an mpp/spp write instruction.

    Args:
        fuzzerstate: The fuzzer's current state object, tracking privilege level,
            register allocation, and memory layout.

    Returns:
        list: A list of generated instruction objects.
    """
    fuzzerstate.init_new_bb() # Update fuzzer state to support a new basic block

    # This points to the first address after the current basic block allocation. 
    # The block allocation takes 16 bytes in advance, to avoid storing and then not being able to continue expanding the basic block.
    curr_alloc_cursor = fuzzerstate.curr_bb_start_addr + BASIC_BLOCK_MIN_SPACE

    # This is used in case there is only space for control flow
    curr_isa_class = None 

    # count for compressed instr in this bb
    bb_id = len(fuzzerstate.bb_start_addr_seq) - 1
    fuzzerstate.bb_compressed_count[bb_id] = 0

    # --------------------------------------
    # Main loop for basic block generation
    # --------------------------------------
    while fuzzerstate.memview.get_available_contig_space(curr_alloc_cursor)-4 > BASIC_BLOCK_MIN_SPACE:

        # DEBUG
        # breakpoint_bb_id    = 6
        # breakpoint_instr_id = 13
        # print('Currently generating bb', len(fuzzerstate.bb_start_addr_seq) - 1, 'instr', len(fuzzerstate.instr_objs_seq[-1]))
        # if len(fuzzerstate.bb_start_addr_seq) - 1 == breakpoint_bb_id and len(fuzzerstate.instr_objs_seq[-1]) == breakpoint_instr_id:
        #     print('breakpoint reached at bb', breakpoint_bb_id, 'instr', breakpoint_instr_id)

        # reset every loop
        fuzzerstate.curr_branch_taken = False
        iscompressed = False

        # Get the next instruction class
        if fuzzerstate.has_reached_max_instr_num():
            curr_isa_class = ISAInstrClass.JAL
        else:
            curr_isa_class = gen_next_isainstrclass(fuzzerstate)

        # curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1])
        curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1]) - 2*fuzzerstate.bb_compressed_count[bb_id]
        if DO_ASSERT:
            assert curr_alloc_cursor == curr_addr + BASIC_BLOCK_MIN_SPACE, f"Curr alloc cursor {hex(curr_alloc_cursor)} does not match expected value {hex(fuzzerstate.curr_bb_start_addr + BASIC_BLOCK_MIN_SPACE)}"

        
        # DEBUG
        # print(hex(curr_alloc_cursor))
        # if (curr_addr) == 0x38272:
            # print(1234)

        # -------------------------------------------------------------------------
        # Case 1: Handle FREE, PRODUCER, CONSUMED Regs
        #         These instructions are designed to increase register dependency depth.
        #         *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        if curr_isa_class == ISAInstrClass.REGFSM:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4

            new_instrobjs = create_regfsm_instrobjs(fuzzerstate)
            fuzzerstate.instr_objs_seq[-1].append(new_instrobjs[0])

            # For consumers, we may need to insert one more instruction
            for next_instrobj_id in range(1, len(new_instrobjs)):
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
                curr_alloc_cursor += 4
                fuzzerstate.instr_objs_seq[-1].append(new_instrobjs[next_instrobj_id])
            del new_instrobjs # For safety, we prevent accidental reuse of this variable
            continue
        
        # -------------------------------------------------------------------------
        # Case 2: Handle FPU FSM instructions
        #         These control FPU enable/disable and rounding mode transitions.
        #         *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.FPUFSM:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4

            new_instrobjs = gen_fpufsm_instrs(fuzzerstate)
            if len(new_instrobjs) == 1: # Equivalent to FPU enable/disable
                fuzzerstate.fpuendis_coords.append((len(fuzzerstate.instr_objs_seq)-1, len(fuzzerstate.instr_objs_seq[-1])))
            if DO_ASSERT:
                assert len(new_instrobjs) * 4 < BASIC_BLOCK_MIN_SPACE # NO_COMPRESSED
            fuzzerstate.instr_objs_seq[-1] += new_instrobjs
            if len(new_instrobjs) > 1:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4*(len(new_instrobjs)-1)) # NO_COMPRESSED
                curr_alloc_cursor += 4*(len(new_instrobjs)-1) # NO_COMPRESSED
            del new_instrobjs # For safety, we prevent accidental reuse of this variable
            continue

        # -------------------------------------------------------------------------
        # Case 3: mret and sret
        #         Never used right now, TODO
        #         *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.DESCEND_PRV:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4

            # print('Priv descent at addr', hex(curr_addr), 'privstate', fuzzerstate.privilegestate.privstate)
            new_instrobj = gen_priv_descent_instr(fuzzerstate)
            # print('  New privstate', fuzzerstate.privilegestate.privstate)

            # Create space for the next basic block.
            if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                # Abort the bb
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                return False
            fuzzerstate.instr_objs_seq[-1].append(new_instrobj)
            del new_instrobj
            return True
        
        # -------------------------------------------------------------------------
        # Case 4: Set MPP and SPP to M/S/U randomly
        #         Only used when activate privilege
        #         *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.PPFSM:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4

            new_instrobjs = gen_ppfill_instrs(fuzzerstate)
            if DO_ASSERT:
                assert len(new_instrobjs) * 4 < BASIC_BLOCK_MIN_SPACE # NO_COMPRESSED
            fuzzerstate.instr_objs_seq[-1] += new_instrobjs
            if len(new_instrobjs) > 1:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4*(len(new_instrobjs)-1)) # NO_COMPRESSED
                curr_alloc_cursor += 4*(len(new_instrobjs)-1) # NO_COMPRESSED
            del new_instrobjs # For safety, we prevent accidental reuse of this variable
            continue

        # -------------------------------------------------------------------------
        # Case 5: Exception instr
        #         *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.EXCEPTION:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4

            # Create space for the next basic block.
            if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                # Abort the bb
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                return False
            # for execptions, we return a list of instr
            new_instrobjs = gen_next_exception_instr_from_instr_illegal_type(fuzzerstate, curr_addr)
            if DO_ASSERT:
                assert len(new_instrobjs) * 4 < BASIC_BLOCK_MIN_SPACE # NO_COMPRESSED
            fuzzerstate.instr_objs_seq[-1] += new_instrobjs
            if len(new_instrobjs) > 1:
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4*(len(new_instrobjs)-1)) # NO_COMPRESSED
                curr_alloc_cursor += 4*(len(new_instrobjs)-1) # NO_COMPRESSED

            # -------------------------------------------------------------------------
            # SnapFuzz: continue or go to the final block immediately
            # -------------------------------------------------------------------------
            if getattr(new_instrobjs[-1], "terminal_exception", False) or random.random() < PROBA_STOP_ON_EXCEPTION:
                jump_addr = curr_addr + 4*len(new_instrobjs)
                fuzzerstate.instr_objs_seq[-1].append(JALInstruction("jal", 0, fuzzerstate.final_bb_base_addr-jump_addr, fuzzerstate.is_design_64bit))
                fuzzerstate.next_bb_addr = None
                return True
            del new_instrobjs # For safety, we prevent accidental reuse of this variable
            continue

        # -------------------------------------------------------------------------
        # Case 6.1: JAL and JALR
        #           *** HAS compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.JALR):
            # If this was a JAL due to reaching the max authorized number of instructions
            if curr_isa_class == ISAInstrClass.JAL and fuzzerstate.has_reached_max_instr_num():
                gen_bb_addr_ret = gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr)
                assert gen_bb_addr_ret, "We should have returned earlier if we reached the max number of instructions."

                instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)
                assert instr_str == 'jal', f"Unexpected instruction string `{instr_str}`"
                
                new_instr, iscompressed = create_instr("jal", fuzzerstate, curr_addr)
                fuzzerstate.instr_objs_seq[-1].append(new_instr)

            # NOTICE: We dont need to alloc space here, because this is the last instr of the bb
            #         We already allocated BASIC_BLOCK_MIN_SPACE in advance
                # if iscompressed:
                #     fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+2)
                #     curr_alloc_cursor += 2
                #     fuzzerstate.bb_compressed_count[bb_id] += 1
                # else:
                #     fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
                #     curr_alloc_cursor += 4  

                return True
            
            # Gen the next bb addr
            if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                # If we can't find space for the next bb, abort this bb
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                return False
            
            instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)            
            next_instr, iscompressed = create_instr(instr_str, fuzzerstate, curr_addr, iscompressed)
            fuzzerstate.instr_objs_seq[-1].append(next_instr)

            # Allocate the next bytes
            # NOTICE: We dont need to alloc space here, because jal/jalr is the last instr of the bb
            #         We already allocated BASIC_BLOCK_MIN_SPACE in advance
            if iscompressed:
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+2)
                # curr_alloc_cursor += 2
                fuzzerstate.bb_compressed_count[bb_id] += 1
            # else:
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
                # curr_alloc_cursor += 4

        # -------------------------------------------------------------------------
        # Case 6.2: BRANCH, these branch instr has different 
        #           *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.BRANCH:

            fuzzerstate.curr_branch_taken = random.random() < BRANCH_TAKEN_PROBA

            if fuzzerstate.curr_branch_taken:
                # Gen the next bb addr
                if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
                    # If we can't find space for the next bb, abort this bb
                    fuzzerstate.instr_objs_seq.pop()
                    fuzzerstate.bb_start_addr_seq.pop()
                    fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
                    return False
                # NOTICE: We dont need to alloc space here, because if curr_branch_taken, this is the last instr of the bb
                #         We already allocated BASIC_BLOCK_MIN_SPACE in advance
                # fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            
            else: 
                # Allocate the next 4 bytes
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
                curr_alloc_cursor += 4

            instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)            
            next_instr = create_instr(instr_str, fuzzerstate, curr_addr, iscompressed)
            fuzzerstate.instr_objs_seq[-1].append(next_instr)

        # -------------------------------------------------------------------------
        # Case 7: medeleg
        # We have some special cases for instructions that are not entirely characterized by an instruction string
        #           *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.MEDELEG:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4

            # Just a safety measure to ensure we don't use a stale one by mistake
            next_instr = None 
            if DO_ASSERT:
                assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE, "medeleg can only be used in machine mode, and we do not an exception here."
            next_instr = gen_medeleg_instr(fuzzerstate)
            fuzzerstate.instr_objs_seq[-1].append(next_instr)

        # -------------------------------------------------------------------------
        # Case 8: mtvec/stvec, mepc/sepc fill instr will NOT generated by random
        # Instead, I will manually fill them, only when we generated a execption
        # -------------------------------------------------------------------------
        # elif curr_isa_class == ISAInstrClass.TVECFSM:
        #     next_instr = gen_tvecfill_instr(fuzzerstate)
        # elif curr_isa_class == ISAInstrClass.EPCFSM:
        #     next_instr = gen_epcfill_instr(fuzzerstate)

        # -------------------------------------------------------------------------
        # Case 9: Random CSR, don't know functionality yet TODO
        # privileged descent instruction or an mpp/spp write instruction.
        #           *** NO compressed instr here ***
        # -------------------------------------------------------------------------
        elif curr_isa_class == ISAInstrClass.RANDOM_CSR:
            # Allocate the next 4 bytes
            fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
            curr_alloc_cursor += 4
            
            next_instr = gen_random_csr_op(fuzzerstate)
            fuzzerstate.instr_objs_seq[-1].append(next_instr)
        
        # -------------------------------------------------------------------------
        # Case 10: "Traditional cases" ALU, ALU64, FPU ......
        #           *** HAS compressed instr here ***
        # -------------------------------------------------------------------------   
        else:
            instr_str = gen_next_instrstr_from_isaclass(curr_isa_class, fuzzerstate)            
            # Decide if compressed
            if instr_str.startswith('c.'):
                # Allocate the next 2 bytes
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+2)
                curr_alloc_cursor += 2

                iscompressed = True
                fuzzerstate.bb_compressed_count[bb_id] += 1
            else:
                # Allocate the next 4 bytes
                fuzzerstate.memview.alloc_mem_range(curr_alloc_cursor, curr_alloc_cursor+4)
                curr_alloc_cursor += 4

            next_instr = create_instr(instr_str, fuzzerstate, curr_addr, iscompressed)

            fuzzerstate.instr_objs_seq[-1].append(next_instr)

        if curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.JALR) or fuzzerstate.curr_branch_taken:
            return True
    # --- end of while loop ---
        
    # -------------------------------------------------------------------------
    # This is reached if get_available_contig_space(curr_alloc_cursor)-4 < BASIC_BLOCK_MIN_SPACE, means we dont have enough space
    # We need to urgently jump to the next basic block.
    # The algorithm is the following: if there is a possibility to jump immediately, then do so. Else, prepare the registers as fast as possible.
    # -------------------------------------------------------------------------
    curr_isa_class = random.choices([ISAInstrClass.JAL, ISAInstrClass.JALR, ISAInstrClass.BRANCH], [1, 1, 1], k=1)[0]
    curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1]) -2*fuzzerstate.bb_compressed_count[bb_id]

    # No need for any preparation if jal, because it has no true dependency
    if curr_isa_class in (ISAInstrClass.JAL, ISAInstrClass.BRANCH):
        # Gen the next bb addr
        if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
            # Abort the bb
            fuzzerstate.instr_objs_seq.pop()
            fuzzerstate.bb_start_addr_seq.pop()
            fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            return False
        if curr_isa_class == ISAInstrClass.JAL:
            new_instr, iscompressed = create_instr("jal", fuzzerstate, curr_addr)
            fuzzerstate.instr_objs_seq[-1].append(new_instr)
        elif curr_isa_class == ISAInstrClass.BRANCH:
            fuzzerstate.curr_branch_taken = True
            # The branch type does not batter because it will be re-determined once the operand values are known
            fuzzerstate.instr_objs_seq[-1].append(create_instr("bne", fuzzerstate, curr_addr))
        else:
            raise ValueError(f"Unexpected isa class `{curr_isa_class}`")

    else:
        # For JALR, bring some reg to maturity, and then insert the control flow instruction
        # Here we dont need to allocate space, because we allocated more space in advance

        if DO_ASSERT:
            assert curr_isa_class == ISAInstrClass.JALR

        fuzzerstate.intregpickstate.bring_some_reg_to_state(IntRegIndivState.CONSUMED, fuzzerstate)

        # Gen the next bb addr
        if not gen_next_bb_addr(fuzzerstate, curr_isa_class, curr_addr):
            # Abort the bb
            fuzzerstate.instr_objs_seq.pop()
            fuzzerstate.bb_start_addr_seq.pop()
            fuzzerstate.intregpickstate.restore_state(fuzzerstate.saved_reg_states[-1])
            return False
        new_instr, iscompressed = create_instr('jalr', fuzzerstate, curr_addr)
        fuzzerstate.instr_objs_seq[-1].append(new_instr)

        


# =============================================================================================================
# These must be done early, say, just after generating the initial block, to ensure that we have enough space.
# =============================================================================================================
def alloc_random_data_block(fuzzerstate: 'FuzzerState'):
    lenbytes = random.randrange(RANDOM_DATA_BLOCK_MIN_SIZE_BYTES, RANDOM_DATA_BLOCK_MAX_SIZE_BYTES)
    # INITIAL_BLOCK_MAX_SIZE_BYTES*4 save space for initial block
    fuzzerstate.random_data_block_start_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, INITIAL_BLOCK_MAX_SIZE_BYTES*4, fuzzerstate.memsize)
    fuzzerstate.random_data_block_end_addr = fuzzerstate.random_data_block_start_addr + lenbytes
    if DO_ASSERT:
        assert fuzzerstate.random_data_block_start_addr is not None, f"Maybe you should create the random data block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.random_data_block_start_addr, fuzzerstate.random_data_block_end_addr)
    # Generate the random data
    for _ in range(fuzzerstate.random_data_block_start_addr, fuzzerstate.random_data_block_end_addr, 4):
        fuzzerstate.random_block_content4by4bytes.append(random.randrange(0, 2**32))

def alloc_reg_context_saver_block(fuzzerstate: 'FuzzerState'):
    # every reg takes 8 bytes for a sd instruction
    lenbytes = ( MAX_NUM_PICKABLE_REGS + MAX_NUM_PICKABLE_FLOATING_REGS ) * 8
    # INITIAL_BLOCK_MAX_SIZE_BYTES*4 save space for initial block
    fuzzerstate.reg_context_saver_block_start_addr = fuzzerstate.memview.gen_random_free_addr(3, lenbytes, INITIAL_BLOCK_MAX_SIZE_BYTES*4, fuzzerstate.memsize)
    fuzzerstate.reg_context_saver_block_end_addr = fuzzerstate.reg_context_saver_block_start_addr + lenbytes
    if DO_ASSERT:
        assert fuzzerstate.reg_context_saver_block_start_addr is not None, f"Maybe you should create the reg context saver block earlier in the creation of the test case."
    # We only need to alloc mem for this block, no need to save value in it
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.reg_context_saver_block_start_addr, fuzzerstate.reg_context_saver_block_end_addr)

def alloc_final_basic_block(fuzzerstate: 'FuzzerState'):
    lenbytes = get_finalblock_max_size() * 4 # NO_COMPRESSED
    # INITIAL_BLOCK_MAX_SIZE_BYTES*4 save space for initial block
    fuzzerstate.final_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, INITIAL_BLOCK_MAX_SIZE_BYTES*4, fuzzerstate.memsize)
    if DO_ASSERT:
        assert fuzzerstate.final_bb_base_addr is not None, f"Maybe you should create the final basic block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.final_bb_base_addr, fuzzerstate.final_bb_base_addr+lenbytes)

def alloc_trap_handler_block(fuzzerstate: 'FuzzerState'):
    lenbytes = get_trap_handler_block_size() * 4 # NO_COMPRESSED
    # INITIAL_BLOCK_MAX_SIZE_BYTES*4 save space for initial block
    fuzzerstate.trap_handler_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, INITIAL_BLOCK_MAX_SIZE_BYTES*4, fuzzerstate.memsize)
    if DO_ASSERT:
        assert fuzzerstate.trap_handler_bb_base_addr is not None, f"Maybe you should create the trap handler block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.trap_handler_bb_base_addr, fuzzerstate.trap_handler_bb_base_addr+lenbytes)

def alloc_trap_handler_ill_instr_block(fuzzerstate: 'FuzzerState'):
    lenbytes = get_trap_handler_block_size() * 4 # NO_COMPRESSED
    # INITIAL_BLOCK_MAX_SIZE_BYTES*4 save space for initial block
    fuzzerstate.trap_handler_ill_instr_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, lenbytes, INITIAL_BLOCK_MAX_SIZE_BYTES*4, fuzzerstate.memsize)
    if DO_ASSERT:
        assert fuzzerstate.trap_handler_ill_instr_bb_base_addr is not None, f"Maybe you should create the trap handler ill instr block earlier in the creation of the test case."
    fuzzerstate.memview.alloc_mem_range(fuzzerstate.trap_handler_ill_instr_bb_base_addr, fuzzerstate.trap_handler_ill_instr_bb_base_addr+lenbytes)

def alloc_page_table(fuzzerstate: 'FuzzerState'):
    """
    Allocate 4KiB-aligned pages for an Sv39 page table (identity mapping).
    Uses 3-level (4KB pages) when memsize allows, otherwise 2-level (megapages).
    This exercises the full page table walker depth in the TLB/MMU.
    """
    if not fuzzerstate.design_has_supervisor_mode or not fuzzerstate.is_design_64bit:
        return
    # Enable VM for ~50% of tests using seed parity (avoids consuming main RNG)
    if fuzzerstate.randseed % 2 != 0:
        return

    # Try 3-level first (needs 3 pages = 12KB), fall back to 2-level (2 pages = 8KB)
    left_bound = INITIAL_BLOCK_MAX_SIZE_BYTES * 4
    aligned_left = (left_bound + 4095) >> 12
    pt_addr = None
    for lenbytes in (PAGE_TABLE_SIZE_3LEVEL, PAGE_TABLE_SIZE_2LEVEL):
        # MemoryView samples an exclusive upper bound after page alignment.
        if aligned_left >= ((fuzzerstate.memsize - lenbytes) >> 12):
            continue
        pt_addr = fuzzerstate.memview.gen_random_free_addr(12, lenbytes, left_bound, fuzzerstate.memsize)
        if pt_addr is not None:
            break
    if pt_addr is None:
        return  # Not enough space, skip VM for this test
    use_3level = lenbytes == PAGE_TABLE_SIZE_3LEVEL

    fuzzerstate.page_table_base_offset = pt_addr
    fuzzerstate.memview.alloc_mem_range(pt_addr, pt_addr + lenbytes)
    fuzzerstate.vm_enabled = True

    root_addr = pt_addr          # L2 root page table
    l1_addr   = pt_addr + 4096   # L1 page table for DRAM region

    # L2 root table:
    # root[1]: VA 0x40000000-0x7FFFFFFF -> PA same (gigapage, I/O space)
    PTE_IO = 0x100000D7  # PPN=0x40000, D=1,A=1,U=1,R=1,W=1,V=1
    fuzzerstate.page_table_data[root_addr + 1*8] = PTE_IO

    # root[2]: VA 0x80000000-0xBFFFFFFF -> pointer to L1 table (non-leaf)
    l1_phys = fuzzerstate.design_base_addr + l1_addr
    l1_ppn  = l1_phys >> 12
    PTE_L1_PTR = (l1_ppn << 10) | 0x01  # V=1, no R/W/X = non-leaf
    fuzzerstate.page_table_data[root_addr + 2*8] = PTE_L1_PTR

    if use_3level:
        # 3-level: L1 points to L0 table, L0 has 4KB page mappings
        l0_addr = pt_addr + 8192  # L0 page table
        l0_phys = fuzzerstate.design_base_addr + l0_addr
        l0_ppn  = l0_phys >> 12

        # L1[0] -> L0 table (non-leaf, covers 0x80000000-0x801FFFFF)
        PTE_L0_PTR = (l0_ppn << 10) | 0x01  # V=1, non-leaf
        fuzzerstate.page_table_data[l1_addr + 0*8] = PTE_L0_PTR

        # L0: identity-mapped 4KB pages for the first 2MB
        num_4k_pages = min(512, (fuzzerstate.memsize + 4095) >> 12)
        for i in range(num_4k_pages):
            pa = fuzzerstate.design_base_addr + (i << 12)
            ppn = pa >> 12
            PTE_4K = (ppn << 10) | 0xDF  # D=1,A=1,U=1,X=1,R=1,W=1,V=1
            fuzzerstate.page_table_data[l0_addr + i*8] = PTE_4K

        # L1[1..N]: 2MB megapages for remaining DRAM beyond first 2MB
        num_megapages = (fuzzerstate.memsize + (1 << 21) - 1) >> 21
        for i in range(1, num_megapages):
            pa = fuzzerstate.design_base_addr + (i << 21)
            ppn = pa >> 12
            PTE_MEGA = (ppn << 10) | 0xDF
            fuzzerstate.page_table_data[l1_addr + i*8] = PTE_MEGA
    else:
        # 2-level: L1 has 2MB megapage mappings
        num_megapages = (fuzzerstate.memsize + (1 << 21) - 1) >> 21
        num_megapages = max(num_megapages, 1)
        for i in range(num_megapages):
            pa = fuzzerstate.design_base_addr + (i << 21)
            ppn = pa >> 12
            PTE_MEGA = (ppn << 10) | 0xDF  # D=1,A=1,U=1,X=1,R=1,W=1,V=1
            fuzzerstate.page_table_data[l1_addr + i*8] = PTE_MEGA

# def alloc_context_saver_bb(fuzzerstate):
#     # For the contextsaver, we first want to know the base address before we generate the basic block because we do loads and stores, which require absolute addresses.
#     fuzzerstate.ctxsv_bb_base_addr = fuzzerstate.memview.gen_random_free_addr(2, fuzzerstate.ctxsv_size_upperbound, 0, fuzzerstate.memsize)
#     if fuzzerstate.ctxsv_bb_base_addr is None:
#         return False
#     fuzzerstate.memview.alloc_mem_range(fuzzerstate.ctxsv_bb_base_addr, fuzzerstate.ctxsv_bb_base_addr+fuzzerstate.ctxsv_size_upperbound)
#     return True

def gen_memop_addrs(fuzzerstate: 'FuzzerState'):
    """
    Returns:
        A list of addresses for the memory operations, in their order of occurrence
    """
    ret = []
    for bb_instrlist in fuzzerstate.instr_objs_seq:
        for bb_instr in bb_instrlist:
            if is_placeholder(bb_instr):
                continue
            elif bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM] or \
                 bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEM64] or \
                 bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPU] or \
                 bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.MEMFPUD] or \
                 bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.AMO] or \
                 bb_instr.instr_str in INSTRUCTIONS_BY_ISA_CLASS[ISAInstrClass.AMO64]:
                ret.append(pick_memop_addr(fuzzerstate, is_instrstr_load(bb_instr.instr_str), get_alignment_bits(bb_instr.instr_str)))
    return ret


def gen_basicblocks(fuzzerstate: 'FuzzerState'):
    while True:
        fuzzerstate.reset()
        
        # Reserve space for data and blocks
        alloc_random_data_block(fuzzerstate)
        alloc_reg_context_saver_block(fuzzerstate)
        alloc_trap_handler_block(fuzzerstate)
        alloc_trap_handler_ill_instr_block(fuzzerstate)
        alloc_final_basic_block(fuzzerstate)

        # Enable translation after MEM moves 2.5 percentage points from startup.
        if fuzzerstate.memory_expansion_enabled:
            alloc_page_table(fuzzerstate)

        # Initial Block
        # I think initial block can add some c. instr TODO
        gen_initial_basic_block(fuzzerstate, SPIKE_STARTADDR)
        fuzzerstate.saved_reg_states.append(fuzzerstate.intregpickstate.save_curr_state())

        if DO_ASSERT:
            assert fuzzerstate.get_num_fuzzing_instructions_sofar() == 0, "We should have generated only one basic block so far."
            assert fuzzerstate.has_reached_max_instr_num() == False,      "We should not have reached the max number of instructions yet."

        # Reserve space for the second basic block (whose address is already fixed).
        fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)

        # For reduction
        # Reserve space for the context setter basic block, but do not instantiate it because we do not know yet what it will look like until we have a concrete context to restore. Until then, we just know arbitrary bounds.
        # if not alloc_context_saver_bb(fuzzerstate):
            # continue

        # generate some blank addr for store op
        fuzzerstate.memstorestate.init_store_locations(fuzzerstate.num_store_locations, fuzzerstate.memview)

        while True:
            gen_basicblock(fuzzerstate)
            if fuzzerstate.next_bb_addr is None:
                # Generation stopped after an exception, or allocation of the next block failed.
                break
            # Save the register states
            fuzzerstate.saved_reg_states.append(fuzzerstate.intregpickstate.save_curr_state())
            if fuzzerstate.nmax_bbs is not None and len(fuzzerstate.instr_objs_seq) >= fuzzerstate.nmax_bbs \
                  or fuzzerstate.memview.get_allocated_ratio() >= LIMIT_MEM_SATURATION_RATIO \
                  or fuzzerstate.has_reached_max_instr_num():
                break
            fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)

        pop_success = pop_last_bbs_to_connect_with_final_block(fuzzerstate)
        if pop_success:
            break

    fuzzerstate.trap_handler_ill_instr_bb = trap_handler_ill_instr_block(fuzzerstate)
    fuzzerstate.trap_handler_bb           = trap_handler_block(fuzzerstate)
    fuzzerstate.final_bb                  = finalblock(fuzzerstate, fuzzerstate.design_name)

    # ------------------------------------------------------------------
    # For these blocks  1. instructions change between spike resolution and RTL sim.
    #                   2. final block addr 
    #                   3. context_setter addr(for reduction)
    #                   4. trap handler
    # we MUST avoid writing to their addr
    # ------------------------------------------------------------------

    blacklist_changing_instructions(fuzzerstate)
    blacklist_final_block(fuzzerstate) 
    blacklist_trap_handler(fuzzerstate)
    blacklist_trap_handler_ill_instr(fuzzerstate)
    blacklist_reg_context_saver(fuzzerstate)
    # blacklist_context_setter(fuzzerstate)

    # Generate addresses for memory operations
    memop_addrs = gen_memop_addrs(fuzzerstate)
    # for i in memop_addrs:
        # print(f"Memop addr: {hex(i)}")

    # If an instr has a producer ID, we have to fill in the addr (lead to another block)
    fuzzerstate.producer_id_to_tgtaddr, fuzzerstate.producer_id_to_noreloc_spike = gen_producer_id_to_tgtaddr(fuzzerstate, memop_addrs)
    # for k, v in fuzzerstate.producer_id_to_tgtaddr.items():
    #     print(f"Producer ID {k} -> target addr {hex(v)}")

    return fuzzerstate


# ================================================================================================================================
# This module is responsible for blacklisting addresses, aka strong allocations.
# Blacklisting is typically used for forbidding loads from loading instructions that will change between spike resolution and RTL sim.
# All functions whose bytecode depends on the is_spike_resolution boolean
# ================================================================================================================================
INSTRUCTION_TYPES_TO_BLACKLIST = [
    BranchInstruction,
    PlaceholderProducerInstr0,
    PlaceholderProducerInstr1,
    PlaceholderConsumerInstr
]

def blacklist_changing_instructions(fuzzerstate: 'FuzzerState'):
    """
    Blacklist addresses where instructions change between spike resolution and RTL sim.
    """
    # The first two instructions set up the relocator reg and may change betweend spike and rtl.
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.bb_start_addr_seq[0], fuzzerstate.bb_start_addr_seq[0]+8) # NO_COMPRESSED

    for bb_id, bb_instrlist in enumerate(fuzzerstate.instr_objs_seq):
        curr_addr = fuzzerstate.bb_start_addr_seq[bb_id]
        for bb_instr_id, bb_instr in enumerate(bb_instrlist):
            # DEBUG
            # if curr_addr == 93472:
                # print(1234)

            # Iterate through INSTRUCTION_TYPES_TO_BLACKLIST
            for instr_type_to_blacklist in INSTRUCTION_TYPES_TO_BLACKLIST:
                if isinstance(bb_instr, instr_type_to_blacklist):
                    if bb_instr.iscompressed:
                        fuzzerstate.memview_blacklist.alloc_mem_range(curr_addr, curr_addr+2)
                    else:
                        fuzzerstate.memview_blacklist.alloc_mem_range(curr_addr, curr_addr+4)
                    break
            if bb_instr.iscompressed:
                curr_addr +=2
            else:
                curr_addr +=4
    
    # Blacklist the last instruction of the initial block because we may steer it into other blocks (typically to the context setter before steering the control flow to a later bb, skipping some first ones).
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.bb_start_addr_seq[0] + (len(fuzzerstate.instr_objs_seq[0]) - 1) * 4, fuzzerstate.bb_start_addr_seq[0] + len(fuzzerstate.instr_objs_seq[0]) * 4) # NO_COMPRESSED

# Blacklist addresses where instructions change between spike resolution and RTL sim.
def blacklist_final_block(fuzzerstate: 'FuzzerState'):
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.final_bb_base_addr, fuzzerstate.final_bb_base_addr + len(fuzzerstate.final_bb) * 4) # NO_COMPRESSED

# Blacklist addresses where instructions change between spike resolution and RTL sim.
def blacklist_context_setter(fuzzerstate: 'FuzzerState'):
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.ctxsv_bb_base_addr, fuzzerstate.ctxsv_bb_base_addr + fuzzerstate.ctxsv_size_upperbound) # NO_COMPRESSED

def blacklist_trap_handler(fuzzerstate: 'FuzzerState'):
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.trap_handler_bb_base_addr, fuzzerstate.trap_handler_bb_base_addr + len(fuzzerstate.trap_handler_bb) * 4) # NO_COMPRESSED

def blacklist_trap_handler_ill_instr(fuzzerstate: 'FuzzerState'):
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.trap_handler_ill_instr_bb_base_addr, fuzzerstate.trap_handler_ill_instr_bb_base_addr + len(fuzzerstate.trap_handler_ill_instr_bb) * 4) # NO_COMPRESSED

def blacklist_reg_context_saver(fuzzerstate: 'FuzzerState'):
    fuzzerstate.memview_blacklist.alloc_mem_range(fuzzerstate.reg_context_saver_block_start_addr, fuzzerstate.reg_context_saver_block_end_addr) # NO_COMPRESSED








"""
# ==============================
# For reduction 
# ==============================
def gen_basicblocks_for_reduction(fuzzerstate: 'FuzzerState', bb_count):

    while True:
        fuzzerstate.reset()
        
        # Reserve space for data and blocks
        alloc_random_data_block(fuzzerstate)
        alloc_reg_context_saver_block(fuzzerstate)
        alloc_trap_handler_block(fuzzerstate)
        alloc_trap_handler_ill_instr_block(fuzzerstate)
        alloc_final_basic_block(fuzzerstate)
        alloc_page_table(fuzzerstate)

        # Initial Block
        # I think initial block can add some c. instr TODO
        gen_initial_basic_block(fuzzerstate, SPIKE_STARTADDR)
        fuzzerstate.saved_reg_states.append(fuzzerstate.intregpickstate.save_curr_state())

        if DO_ASSERT:
            assert fuzzerstate.get_num_fuzzing_instructions_sofar() == 0, "We should have generated only one basic block so far."
            assert fuzzerstate.has_reached_max_instr_num() == False,      "We should not have reached the max number of instructions yet."

        # Reserve space for the second basic block (whose address is already fixed).
        fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)

        # For reduction
        # Reserve space for the context setter basic block, but do not instantiate it because we do not know yet what it will look like until we have a concrete context to restore. Until then, we just know arbitrary bounds.
        # if not alloc_context_saver_bb(fuzzerstate):
            # continue

        # generate some blank addr for store op
        fuzzerstate.memstorestate.init_store_locations(fuzzerstate.num_store_locations, fuzzerstate.memview)

        stop_at_this_block = False
        while True:
            if bb_count != None and len(fuzzerstate.bb_start_addr_seq) >= bb_count:
                stop_at_this_block = True
            
            gen_basicblock(fuzzerstate)

            if stop_at_this_block == True:
                is_last_instr_compressed = fuzzerstate.instr_objs_seq[-1][-1].iscompressed

                curr_addr = fuzzerstate.curr_bb_start_addr + 4*len(fuzzerstate.instr_objs_seq[-1]) -2*fuzzerstate.bb_compressed_count[len(fuzzerstate.bb_start_addr_seq)-1 + 2*is_last_instr_compressed]

                # Replace the last instruction with an jal to final block
                offset_to_final_bb = fuzzerstate.final_bb_base_addr - curr_addr
                fuzzerstate.instr_objs_seq.pop()
                fuzzerstate.bb_start_addr_seq.pop()
                fuzzerstate.instr_objs_seq[-1][-1] = JALInstruction("jal", 0, offset_to_final_bb, fuzzerstate.is_design_64bit)
                break
            
            if fuzzerstate.next_bb_addr is None:
                # This corresponds to failing to find space for a new basic block. In this case, this block may also not have completed, and we drop it.
                break
            # Save the register states
            fuzzerstate.saved_reg_states.append(fuzzerstate.intregpickstate.save_curr_state())
            if fuzzerstate.nmax_bbs is not None and len(fuzzerstate.instr_objs_seq) >= fuzzerstate.nmax_bbs \
                  or fuzzerstate.memview.get_allocated_ratio() >= LIMIT_MEM_SATURATION_RATIO \
                  or fuzzerstate.has_reached_max_instr_num():
                break
            fuzzerstate.memview.alloc_mem_range(fuzzerstate.next_bb_addr, fuzzerstate.next_bb_addr+BASIC_BLOCK_MIN_SPACE)

        if stop_at_this_block:
            break
        
        pop_success = pop_last_bbs_to_connect_with_final_block(fuzzerstate)
        if pop_success:
            break

    fuzzerstate.trap_handler_ill_instr_bb = trap_handler_ill_instr_block(fuzzerstate)
    fuzzerstate.trap_handler_bb           = trap_handler_block(fuzzerstate)
    fuzzerstate.final_bb                  = finalblock(fuzzerstate, fuzzerstate.design_name)

    # ------------------------------------------------------------------
    # For these blocks  1. instructions change between spike resolution and RTL sim.
    #                   2. final block addr 
    #                   3. context_setter addr(for reduction)
    #                   4. trap handler
    # we MUST avoid writing to their addr
    # ------------------------------------------------------------------
    blacklist_changing_instructions(fuzzerstate)
    blacklist_final_block(fuzzerstate) 
    blacklist_trap_handler(fuzzerstate)
    blacklist_trap_handler_ill_instr(fuzzerstate)
    blacklist_reg_context_saver(fuzzerstate)
    # blacklist_context_setter(fuzzerstate)

    # Generate addresses for memory operations
    memop_addrs = gen_memop_addrs(fuzzerstate)
    # for i in memop_addrs:
        # print(f"Memop addr: {hex(i)}")

    # If an instr has a producer ID, we have to fill in the addr (lead to another block)
    fuzzerstate.producer_id_to_tgtaddr, fuzzerstate.producer_id_to_noreloc_spike = gen_producer_id_to_tgtaddr(fuzzerstate, memop_addrs)
    # for k, v in fuzzerstate.producer_id_to_tgtaddr.items():
    #     print(f"Producer ID {k} -> target addr {hex(v)}")

    return fuzzerstate
"""
