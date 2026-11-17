import random

from generation.Instructions import ISAInstrClass
from common.GetCfgs import *
from params.fuzzparams import *
from initialstate.MemView import MemoryView
from initialstate.MemStoreState import MemStoreState
from initialstate.PrivilegeState import PrivilegeState
from pick.PickReg import IntRegPickState
from pick.PickReg import FloatRegPickState
from pick.PickExceptionOp import ExceptionCauseVal

from generation.Instructions import ISAInstClass_Initial_Boosters, Instr_Groups, Instr_Mapping
from params.fuzzparams import MAX_BASIC_BLOCK_COUNT
from params.runparams import DO_ASSERT
from pick.PickExceptionOp import EXCEPTION_INSTR_INITIAL_BOOSTERS


class FuzzerState:
    def __init__(self, 
                 design_name: str, 
                 design_base_addr: int, 
                 memsize: int, 
                 randseed: int, 
                 nmax_bbs: int, 
                 authorize_privileges: bool, 
                 state_instr_prob: dict = ISAInstClass_Initial_Boosters,
                 nmax_instructions: int = None,  
                 nodependencybias: bool = False
                 ):
        
        self.design_name = design_name
        self.design_base_addr = design_base_addr
        self.memsize = memsize
        self.randseed = randseed
        self.nmax_bbs = nmax_bbs
        self.authorize_privileges = authorize_privileges
        self.nmax_instructions = nmax_instructions
        self.nodependencybias = nodependencybias
        self.state_instr_prob = state_instr_prob

        self.is_design_64bit = not is_design_32bit(design_name)

        self.design_has_compressed_support     : bool = design_has_compressed_support(design_name)
        self.design_has_fpu                    : bool = design_has_float_support(design_name)
        self.design_has_fpud                   : bool = design_has_double_support(design_name)
        self.design_has_muldiv                 : bool = design_has_muldiv_support(design_name)
        self.design_has_amo                    : bool = design_has_atop_support(design_name)
        self.design_has_misaligned_data_support: bool = design_has_misaligned_data_support(design_name)
        self.design_has_supervisor_mode        : bool = design_has_supervisor_mode(design_name)
        self.design_has_user_mode              : bool = design_has_user_mode(design_name)
        self.design_has_pmp                    : bool = design_has_pmp(design_name)


        self.gen_pick_weights(self.state_instr_prob)
        self.reset()
        self.init_design_state()  





    def gen_pick_weights(self, state_instr_prob):
        self.fpuweight = random.random() # Can decrease the overall FPU load to favor other types of instructions
        self.isapickweights = {
            ISAInstrClass.REGFSM:      state_instr_prob[ISAInstrClass.REGFSM],
            ISAInstrClass.FPUFSM:      state_instr_prob[ISAInstrClass.FPUFSM],
            ISAInstrClass.ALU:         state_instr_prob[ISAInstrClass.ALU],
            ISAInstrClass.ALU64:       state_instr_prob[ISAInstrClass.ALU64],
            ISAInstrClass.MULDIV:      state_instr_prob[ISAInstrClass.MULDIV],
            ISAInstrClass.MULDIV64:    state_instr_prob[ISAInstrClass.MULDIV64],
            ISAInstrClass.AMO:         state_instr_prob[ISAInstrClass.AMO],
            ISAInstrClass.AMO64:       state_instr_prob[ISAInstrClass.AMO64],
            ISAInstrClass.JAL :        state_instr_prob[ISAInstrClass.JAL],
            ISAInstrClass.JALR:        state_instr_prob[ISAInstrClass.JALR],
            ISAInstrClass.BRANCH:      state_instr_prob[ISAInstrClass.BRANCH],
            ISAInstrClass.MEM:         state_instr_prob[ISAInstrClass.MEM],
            ISAInstrClass.MEM64:       state_instr_prob[ISAInstrClass.MEM64],
            ISAInstrClass.MEMFPU:      state_instr_prob[ISAInstrClass.MEMFPU]  * self.fpuweight,
            ISAInstrClass.FPU:         state_instr_prob[ISAInstrClass.FPU]     * self.fpuweight,
            ISAInstrClass.FPU64:       state_instr_prob[ISAInstrClass.FPU64]   * self.fpuweight,
            ISAInstrClass.MEMFPUD:     state_instr_prob[ISAInstrClass.MEMFPUD] * self.fpuweight,
            ISAInstrClass.FPUD:        state_instr_prob[ISAInstrClass.FPUD]    * self.fpuweight,
            ISAInstrClass.FPUD64:      state_instr_prob[ISAInstrClass.FPUD64]  * self.fpuweight,
            ISAInstrClass.MEDELEG:     state_instr_prob[ISAInstrClass.MEDELEG],
            ISAInstrClass.TVECFSM:     state_instr_prob[ISAInstrClass.TVECFSM],
            ISAInstrClass.PPFSM:       state_instr_prob[ISAInstrClass.PPFSM],
            ISAInstrClass.EPCFSM:      state_instr_prob[ISAInstrClass.EPCFSM],
            ISAInstrClass.EXCEPTION:   state_instr_prob[ISAInstrClass.EXCEPTION],
            ISAInstrClass.RANDOM_CSR:  state_instr_prob[ISAInstrClass.RANDOM_CSR],
            ISAInstrClass.DESCEND_PRV: state_instr_prob[ISAInstrClass.DESCEND_PRV],
            ISAInstrClass.SPECIAL:     state_instr_prob[ISAInstrClass.SPECIAL],
            ISAInstrClass.SFENCE_VMA:  state_instr_prob[ISAInstrClass.SFENCE_VMA],
        }

        mem_weight = sum(state_instr_prob[Instr_Mapping[name]]
                         for name in Instr_Groups["MEM"])
        mem_share = mem_weight / sum(state_instr_prob.values())
        initial_mem_share = sum(ISAInstClass_Initial_Boosters[Instr_Mapping[name]]
                                for name in Instr_Groups["MEM"]) / sum(ISAInstClass_Initial_Boosters.values())
        self.memory_expansion_enabled = (
            mem_share <= initial_mem_share - 0.025
            or mem_share >= initial_mem_share + 0.025
        )
        # TODO: this weight hasn't been modified yet
        self.exception_instr_pickweights = {
            ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED:        EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTR_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_INSTR_ACCESS_FAULT:           EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTR_ACCESS_FAULT],
            ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION:          EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ILLEGAL_INSTRUCTION],
            ExceptionCauseVal.ID_BREAKPOINT:                   EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_BREAKPOINT],
            ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED:         EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_LOAD_ACCESS_FAULT:            EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_ACCESS_FAULT],
            ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED:    EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_ADDR_MISALIGNED],
            ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT:       EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_ACCESS_FAULT],
            ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE: EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_U_MODE],
            ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE: EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_S_MODE],
            ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE: EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_ENVIRONMENT_CALL_FROM_M_MODE],
            ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT:       EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_INSTRUCTION_PAGE_FAULT],
            ExceptionCauseVal.ID_LOAD_PAGE_FAULT:              EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_LOAD_PAGE_FAULT],
            ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT:         EXCEPTION_INSTR_INITIAL_BOOSTERS[ExceptionCauseVal.ID_STORE_AMO_PAGE_FAULT]
        }

        if self.design_has_fpu:
            # Probability to change rounding mode instead of turning the FPU off
            self.proba_change_rm = random.random()
        self.proba_ebreak_instead_of_ecall = random.random()

        # Numbers of pickable registers
        if self.nodependencybias:
            self.num_pickable_regs = MAX_NUM_PICKABLE_REGS
        else:
            self.num_pickable_regs = random.randint(MIN_NUM_PICKABLE_REGS, MAX_NUM_PICKABLE_REGS)
        
        if self.design_has_fpu:
            # We impose self.num_pickable_floating_regs <= self.num_pickable_regs just because initialblock is easier to write. It also has no impact on the fuzzing quality overall.
            self.num_pickable_floating_regs = random.randint(MIN_NUM_PICKABLE_FLOATING_REGS, min(MAX_NUM_PICKABLE_FLOATING_REGS, self.num_pickable_regs))
        else:
            self.num_pickable_floating_regs = 0 # Just for compatibility. This variable is not used if self.design_has_fpu is False.

        if DO_ASSERT:
            assert self.num_pickable_regs < RELOCATOR_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < RELOCATOR_REGISTER_ID ({RELOCATOR_REGISTER_ID})"
            assert self.num_pickable_regs < RDEP_MASK_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < RDEP_MASK_REGISTER_ID ({RDEP_MASK_REGISTER_ID})"
            assert self.num_pickable_regs < FPU_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < FPU_ENDIS_REGISTER_ID ({FPU_ENDIS_REGISTER_ID})"
            assert self.num_pickable_regs < MPP_BOTH_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < MPP_BOTH_ENDIS_REGISTER_ID ({MPP_BOTH_ENDIS_REGISTER_ID})"
            assert self.num_pickable_regs < MPP_TOP_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < MPP_TOP_ENDIS_REGISTER_ID ({MPP_TOP_ENDIS_REGISTER_ID})"
            assert self.num_pickable_regs < SPP_ENDIS_REGISTER_ID, f"Required self.num_pickable_regs ({self.num_pickable_regs}) < SPP_ENDIS_REGISTER_ID ({SPP_ENDIS_REGISTER_ID})"

        # Registers' initial values
        self.proba_reg_starts_with_zero = random.random() / 10
        if DO_ASSERT:
            assert self.proba_reg_starts_with_zero >= 0.0
            assert self.proba_reg_starts_with_zero <= 1.0
    
    def init_new_bb(self):
        self.instr_objs_seq.append([])

        self.curr_bb_start_addr = self.next_bb_addr
        self.next_bb_addr = None
        self.bb_start_addr_seq.append(self.curr_bb_start_addr)


    def reset(self):

        self.num_store_locations = random.randint(1, MAX_NUM_STORE_LOCATIONS)

        self.memview = MemoryView(self.memsize)
        self.memview_blacklist = MemoryView(self.memsize) # For load blacklist

        self.memstorestate = MemStoreState()
        self.intregpickstate = IntRegPickState(self.num_pickable_regs, self.nodependencybias)
        self.floatregpickstate = FloatRegPickState(self.num_pickable_floating_regs)
        self.privilegestate = PrivilegeState()

        self.curr_branch_taken = False

        # for non-taken branches
        self.random_block_content4by4bytes = []
        self.random_data_block_start_addr = 0
        self.random_data_block_end_addr = 0

        # instr seq
        self.instr_objs_seq = []
        
        # bb seq
        self.curr_bb_start_addr = 0
        self.next_bb_addr = 0
        self.bb_start_addr_seq = []

        # Strictly increasing when we create new producer0, to ensure uniqueness
        self.next_producer_id = 0

        # As a second phase, we will populate the producers with addresses before the spike resolution
        self.producer_id_to_tgtaddr = None            # producer_id_to_tgtaddr[producer_id] = tgt_addr
        self.producer_id_to_noreloc_spike = None

        # Register initial data address and content 
        self.initial_reg_data_addr = -1
        self.initial_reg_data_content = []

        self.saved_reg_states = []

        # Register final data address and content. The final bb is responsible for dumping the the final integer and floating registers.
        self.final_bb = []
        self.final_bb_base_addr = -1
        self.final_csr_ids = []

        # Trap handler
        self.trap_handler_bb = []
        self.trap_handler_bb_base_addr = -1

        self.trap_handler_ill_instr_bb = []
        self.trap_handler_ill_instr_bb_base_addr = -1

        # Save state addr when trap
        self.reg_context_saver_block_start_addr = 0
        self.reg_context_saver_block_end_addr = 0

        # For reduction
        self.ctxsv_bb = []
        self.ctxsv_bb_base_addr = -1
        self.ctxsv_bb_jal_instr_id = -1 # Useful because the last elements in ctxsv_bb are data.
        self.ctxdmp_bb = []
        self.ctxdmp_bb_base_addr = -1
        self.ctxdmp_bb_jal_instr_id = -1 # Useful because the last elements in ctxdmp_bb are data.
    
        # Instructions after the basic blocks, called block tails
        self.block_tail_instrs = [] # List of pairs (instr_obj, instr_addr)

        # Rocket has some inaccuracy in minstret because of ebreak and ecall. Hence, we don't read instret after these 2 instructions.
        self.is_minstret_inaccurate_because_ecall_ebreak = False
        # To avoid having too many fences
        self.special_instrs_count = 0
        # Coordinates of the FPU enable/disable instructions. Only used in program reduction.
        self.fpuendis_coords = []

        self.bb_compressed_count = [0] * MAX_BASIC_BLOCK_COUNT

        # Virtual memory (Sv39 identity mapping)
        self.page_table_base_offset = -1
        self.page_table_data = {}  # {offset: 8-byte int value}
        self.vm_enabled = False

    def init_design_state(self):
        if self.design_has_fpu:
            self.is_fpu_activated = True
            self.proba_turn_on_off_fpu_again = random.random()*0.1 

    # Does not count the initial and final blocks
    def get_num_fuzzing_instructions_sofar(self):
        if len(self.instr_objs_seq) <= 1:
            return 0
        return sum([len(bb) for bb in self.instr_objs_seq[1:]])

    def has_reached_max_instr_num(self):
        if self.nmax_instructions is None:
            return False
        assert self.nmax_instructions > 0, f"self.nmax_instructions ({self.nmax_instructions}) <= 0"
        return self.get_num_fuzzing_instructions_sofar() >= self.nmax_instructions
    
    def instance_to_str(self):
        return f"{self.memview.memsize}_{self.design_name}_{self.randseed}_{self.nmax_bbs}"
    
    def instance_to_str_for_deduction(self):
        return f"{self.memview.memsize}_{self.design_name}_{self.randseed}_{self.nmax_bbs}_{len(self.bb_start_addr_seq)}"
