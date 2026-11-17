from params.runparams import DO_ASSERT, DO_EXPENSIVE_ASSERT
from params.fuzzparams import REGPICK_PROTUBERANCE_RATIO, NUM_MIN_FREE_INTREGS
from pick.CreateInstr import create_targeted_producer0_instrobj, create_targeted_producer1_instrobj, create_targeted_consumer_instrobj
from common.utils import IntRegIndivState

from copy import copy, deepcopy
import math
import numpy as np
import random

# ============================================================================================
# Int Register
# ============================================================================================
class IntRegPickState:
    # no_dependency_bias: only to evaluate the impact of the dependency bias
    def __init__(self, num_pickable_regs: int, no_dependency_bias: bool):
        self.num_pickable_regs = num_pickable_regs
        self.nodependencybias = no_dependency_bias
        self.__reg_weights  = np.ones(self.num_pickable_regs)
        self.__reg_weights /= np.sum(self.__reg_weights)
        self.__reg_states   = [IntRegIndivState.FREE for _ in range(self.num_pickable_regs)]
        # Permits matching sensitive instructions with the producers
        self.__last_producer_ids = np.zeros(self.num_pickable_regs)

        # ------------------------------------------------------
        # For each register, a pair of (basic block id, instr in basic block) that produced the register
        # For example, lui and addi producing the same register
        # ------------------------------------------------------
        self.__last_producer_coords = [[[None, None], [None, None]] for _ in range(self.num_pickable_regs)]
        if DO_ASSERT:
            self.__last_producer_ids.fill(None) # To avoid luckily having offset 0

        # ------------------------------------------------------
        # __regs_in_state_onehot = {}
        #  <IntRegIndivState.FREE: 1>:      array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        #  <IntRegIndivState.PRODUCED0: 2>: array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        #  <IntRegIndivState.PRODUCED1: 3>: array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        #  <IntRegIndivState.CONSUMED: 4>:  array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        #  <IntRegIndivState.UNRELIABLE: 5>:array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        # ------------------------------------------------------
        self.__regs_in_state_onehot = {curr_indiv_state: np.ones(self.num_pickable_regs, np.int8) if (curr_indiv_state == IntRegIndivState.FREE) else np.zeros(self.num_pickable_regs, np.int8) for curr_indiv_state in IntRegIndivState}
        # Will ignore x0 if line below is uncommented. This is a design decision.
        # self.__reg_weights[0] = 0

    def get_free_regs_onehot(self): 
        ret = [int(self.__reg_states[reg_id] == IntRegIndivState.FREE) for reg_id in range(self.num_pickable_regs)]
        if DO_ASSERT:
            assert sum(ret) >= NUM_MIN_FREE_INTREGS
        return ret
    
    def get_free_or_relocused_regs_onehot(self): # WARNING: Use those only for outputs, not for inputs.
        ret = [int(self.__reg_states[reg_id] == IntRegIndivState.FREE) for reg_id in range(self.num_pickable_regs)]
        if DO_ASSERT:
            assert sum(ret) >= NUM_MIN_FREE_INTREGS
        return ret
    
    def get_effective_weights(self, authorized_regs_onehot):
        """
        Weights after deducting the forbidden registers
        """
        if DO_ASSERT:
            assert np.any(authorized_regs_onehot)
        if self.nodependencybias:
            return authorized_regs_onehot
        return self.__reg_weights * authorized_regs_onehot

    def pick_int_inputreg(self, authorize_sideeffects: bool = True):
        """ 
        Returns a free inputreg.
        """
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights(self.get_free_regs_onehot()))[0]
    
    def pick_int_inputreg_nonzero(self, authorize_sideeffects: bool = True):
        """
        Excludes the zero register
        """
        authorized_regs_onehot = self.get_free_regs_onehot()
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        ret = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        authorized_regs_onehot[0] = was_zero_authorized
        return ret
    
    def pick_int_inputreg_prime(self, authorize_sideeffects: bool = True) -> int:
        """
        Pick a compressed integer register (rs'), i.e. x8-x15.
        """
        # Valid rs' registers
        if DO_ASSERT:
            assert self.num_pickable_regs > 8, "Not enough pickable registers to pick rs'"
        valid_regs = range(8, min(16, self.num_pickable_regs))

        weights = self.get_effective_weights(self.get_free_regs_onehot())

        # Restrict weights to rs′ range
        filtered_regs = list(valid_regs)
        filtered_weights = [weights[r] for r in filtered_regs]

        return random.choices(filtered_regs, weights=filtered_weights, k=1)[0]

    def pick_int_inputregs(self, n: int):
        """
        Consuming multiple input registers in one go.
        """
        authorized_regs_onehot = self.get_free_regs_onehot()
        if DO_ASSERT:
            assert n > 1, "The function pick_int_inputregs should not be used for n < 2. For n = 1, please use pick_int_inputreg."
        return random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot), k=n)

    def pick_int_outputreg(self, authorize_sideeffects: bool = True):
        """
        Updates the intregstate.
        """
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() # We could use any, but let's not waste the generated ones
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        return rd
    
    def pick_int_outputreg_nonzero(self, authorize_sideeffects: bool = True):
        # Get a FREE reg
        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot() 
        was_zero_authorized = authorized_regs_onehot[0]
        authorized_regs_onehot[0] = 0
        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."
        rd = random.choices(range(self.num_pickable_regs), self.get_effective_weights(authorized_regs_onehot))[0]
        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd:
                self.set_regstate(rd, IntRegIndivState.FREE)
        authorized_regs_onehot[0] = was_zero_authorized
        return rd

    def pick_int_outputreg_specified(self, specified_reg, authorize_sideeffects: bool = True, force_free_reg: bool = False):
        # pick reg we want
        rd = specified_reg
        if self.__reg_states[rd] != IntRegIndivState.FREE:
            # If the instr change the value of specified reg(means it has authorize_sideeffects) 
            # For example, lwsp, sp is the rd, we nee to set it to FREE
            if authorize_sideeffects:
                self._update_probaweights(rd)
                if rd:
                    self.set_regstate(rd, IntRegIndivState.FREE, force_free_reg)            
            else:
                pass

        return rd

    def pick_int_outputreg_prime(self, authorize_sideeffects: bool = True):
        """
        Pick a compressed output integer register (rd'), i.e. x8–x15.
        """
        if DO_ASSERT:
            assert self.num_pickable_regs > 8, "Not enough pickable registers to pick rs'"
        valid_lo = 8
        valid_hi = min(16, self.num_pickable_regs)

        authorized_regs_onehot = self.get_free_or_relocused_regs_onehot()

        if DO_ASSERT:
            assert np.max(authorized_regs_onehot) == 1, "Unexpectedly, some register was registered in two states at a time."

        # Mask everything except x8–x15
        masked_authorized_regs_onehot = np.zeros_like(authorized_regs_onehot)
        masked_authorized_regs_onehot[valid_lo:valid_hi] = authorized_regs_onehot[valid_lo:valid_hi]

        if DO_ASSERT:
            assert masked_authorized_regs_onehot.any(), "No authorized rs' register available"

        rd = random.choices(range(self.num_pickable_regs),self.get_effective_weights(masked_authorized_regs_onehot),k=1,)[0]

        if authorize_sideeffects:
            self._update_probaweights(rd)
            if rd != 0:
                self.set_regstate(rd, IntRegIndivState.FREE)

        return rd
    
    def _update_probaweights(self, outreg: int):
        """
        Args: 
            outreg: the produced register.
        """
        if DO_ASSERT:
            assert 0 <= outreg
            assert outreg < self.num_pickable_regs
            assert math.isclose(sum(self.__reg_weights), 1, abs_tol=0.001), f"{sum(self.__reg_weights)} {str(self.__reg_weights)}"
        # # Ignore x0
        # if outreg == 0:
        #     return
        # The lines here below are a heuristic algorithm to favor more recently produced registers
        sum_of_others = np.sum(self.__reg_weights) - self.__reg_weights[outreg]
        for reg_id in range(self.num_pickable_regs):
            # We also do it (for performance) for outreg and we overwrite it later
            self.__reg_weights[reg_id] = self.__reg_weights[reg_id] * (1-REGPICK_PROTUBERANCE_RATIO) / sum_of_others
        self.__reg_weights[outreg] = REGPICK_PROTUBERANCE_RATIO
    
    
    def get_regstate(self, reg_id: int):
        """
        Get register state
        
        Returns:
            [IntRegIndivState.FREE, PRODUCED0, PRODUCED1, CONSUMED, UNRELIABLE]
        """
        if DO_ASSERT:
            assert 0 < reg_id
            assert reg_id < self.num_pickable_regs
        return self.__reg_states[reg_id]

    def set_regstate(self, reg_id: int, new_state: int, force: bool = False):
        """
        Args:
            force: do not check compatibility before->after. Used for restoring some saved state, for example.
        """
        if DO_ASSERT:
            assert 0 < reg_id
            assert reg_id < self.num_pickable_regs
            if not force:
                if self.__reg_states[reg_id] == IntRegIndivState.FREE:
                    assert new_state in (IntRegIndivState.FREE, IntRegIndivState.PRODUCED0, IntRegIndivState.CONSUMED)
                elif self.__reg_states[reg_id] == IntRegIndivState.PRODUCED0:
                    assert new_state == IntRegIndivState.PRODUCED1
                elif self.__reg_states[reg_id] == IntRegIndivState.PRODUCED1:
                    assert new_state in (IntRegIndivState.CONSUMED, IntRegIndivState.UNRELIABLE)
                elif self.__reg_states[reg_id] == IntRegIndivState.CONSUMED:
                    assert new_state == IntRegIndivState.FREE
                if DO_EXPENSIVE_ASSERT:
                    # Check that the register is registered in exactly one state
                    for s in IntRegIndivState:
                        assert self.__regs_in_state_onehot[s][reg_id] == int(s == self.__reg_states[reg_id])
                else:
                    assert self.__regs_in_state_onehot[self.__reg_states[reg_id]][reg_id]
        self.__regs_in_state_onehot[self.__reg_states[reg_id]][reg_id] = 0
        self.__regs_in_state_onehot[new_state][reg_id] = 1
        self.__reg_states[reg_id] = new_state

    def bring_some_reg_to_state(self, req_state: int, fuzzerstate, need_prime: bool = False):
        """
        Brings iteratively a register to the requested state, as fast as possible
        
        Returns:
            nothing, but guarantees that a register will be in the target state
        """
        if DO_ASSERT:
            assert req_state == IntRegIndivState.CONSUMED
        if req_state == IntRegIndivState.CONSUMED:
            if self.exists_reg_in_state(IntRegIndivState.CONSUMED, need_prime):
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.PRODUCED1, need_prime):
                fuzzerstate.instr_objs_seq[-1] += create_targeted_consumer_instrobj(fuzzerstate, need_prime)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.PRODUCED0, need_prime):
                fuzzerstate.instr_objs_seq[-1] += create_targeted_producer1_instrobj(fuzzerstate, need_prime)
                # Consumer also includes preconsumer
                fuzzerstate.instr_objs_seq[-1] += create_targeted_consumer_instrobj(fuzzerstate, need_prime)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.FREE, need_prime):
                fuzzerstate.instr_objs_seq[-1] += create_targeted_producer0_instrobj(fuzzerstate, need_prime)
                fuzzerstate.instr_objs_seq[-1] += create_targeted_producer1_instrobj(fuzzerstate, need_prime)
                # Consumer also includes preconsumer
                fuzzerstate.instr_objs_seq[-1] += create_targeted_consumer_instrobj(fuzzerstate, need_prime)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            raise ValueError('Unexpected state.')
        
    def bring_some_reg_to_state_prime(self, req_state: int, fuzzerstate):
        """
        For compress instructions, brings iteratively a PRIME register to the requested state, as fast as possible
        
        Returns:
            nothing, but guarantees that a register will be in the target state
        """
        if DO_ASSERT:
            assert req_state == IntRegIndivState.CONSUMED
        if req_state == IntRegIndivState.CONSUMED:
            if self.exists_reg_in_state(IntRegIndivState.CONSUMED):
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.PRODUCED1):
                fuzzerstate.instr_objs_seq[-1] += create_targeted_consumer_instrobj(fuzzerstate)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.PRODUCED0):
                fuzzerstate.instr_objs_seq[-1] += create_targeted_producer1_instrobj(fuzzerstate)
                # Consumer also includes preconsumer
                fuzzerstate.instr_objs_seq[-1] += create_targeted_consumer_instrobj(fuzzerstate)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            if self.exists_reg_in_state(IntRegIndivState.FREE):
                fuzzerstate.instr_objs_seq[-1] += create_targeted_producer0_instrobj(fuzzerstate)
                fuzzerstate.instr_objs_seq[-1] += create_targeted_producer1_instrobj(fuzzerstate)
                # Consumer also includes preconsumer
                fuzzerstate.instr_objs_seq[-1] += create_targeted_consumer_instrobj(fuzzerstate)
                return # self.pick_int_reg_in_state(IntRegIndivState.CONSUMED)
            raise ValueError('Unexpected state.')

    def save_curr_state(self):
        """
        Save at the end of basic blocks, and restore if popping basic blocks from the end.
        """
        return copy(self.__reg_weights), copy(self.__reg_states), copy(self.__last_producer_ids), deepcopy(self.__last_producer_coords)

    def restore_state(self, saved_state: tuple):
        """
        Rarely called.        
        """
        if DO_ASSERT:
            assert len(saved_state) == 4
        # Restore the reg weights (this is not so important)
        self.__reg_weights = copy(saved_state[0])
        # Restore the reg states. Be careful to also restore the internal matrix. Therefore, use the API function.
        for reg_id in range(1, self.num_pickable_regs):
            self.set_regstate(reg_id, saved_state[1][reg_id], force=True)
        self.__last_producer_ids = copy(saved_state[2])
        self.__last_producer_coords = deepcopy(saved_state[3])

    # =====================================
    # Getters and setters for producer ids 
    # =====================================
    def get_producer_id(self, reg_id: int):
        return self.__last_producer_ids[reg_id]
    
    def set_producer_id(self, reg_id: int, producer_id: int):
        """
        For lui's rd, __last_producer_ids[rd] = producer_id, and producer_id ++
        """
        self.__last_producer_ids[reg_id] = producer_id
    
    def set_producer0_location(self, reg_id: int, bb_id: int, instr_id_in_bb: int):
        self.__last_producer_coords[reg_id][0] = (bb_id, instr_id_in_bb)
    
    def set_producer1_location(self, reg_id: int, bb_id: int, instr_id_in_bb: int):
        self.__last_producer_coords[reg_id][1] = (bb_id, instr_id_in_bb)

    # ========================================
    # Getters for registers in a certain state
    # ========================================
    def exists_reg_in_state(self, req_state: IntRegIndivState, need_prime: bool = False) -> bool:
        if need_prime:
            # x8-x15 → indices 8:16
            return np.any(self.__regs_in_state_onehot[req_state][8:16])
        else:
            return np.any(self.__regs_in_state_onehot[req_state])
    
    def get_num_regs_in_state(self, req_state: IntRegIndivState) -> bool:
        return np.sum(self.__regs_in_state_onehot[req_state])
    
    def pick_int_reg_in_state(self, req_state: IntRegIndivState):
        if DO_ASSERT:
            assert self.exists_reg_in_state(req_state), f"No reg in state `{req_state}`"
        ret = None
        while ret is None or not self.__regs_in_state_onehot[req_state][ret]:
            # choices(range, weights, chosen number)
            ret = random.choices(range(self.num_pickable_regs), self.__regs_in_state_onehot[req_state], k=1)[0]
        return ret
    
    def pick_int_reg_in_state_prime(self, req_state: IntRegIndivState):
        """
        Pick an integer register in `req_state` restricted to compressed range x8-x15.
        """
        valid_regs = range(8, min(16, self.num_pickable_regs))

        # Identify regs in req_state within x8-x15
        candidate_regs = [r for r in valid_regs if self.__regs_in_state_onehot[req_state][r]]

        if DO_ASSERT:
            assert candidate_regs, f"No register in state `{req_state}` within x8-x15"

        return random.choices(candidate_regs, k=1)[0]
    
    def display(self):
        print('pickreg', self.__regs_in_state_onehot)

# ============================================================================================
# Float Register
# Float registers are never forbidden, therefore this is simpler than integer registers.        
# ============================================================================================
class FloatRegPickState:
    def __init__(self, num_pickable_floating_regs: int):
        self.num_pickable_floating_regs = num_pickable_floating_regs
        self.__reg_weights = np.ones(self.num_pickable_floating_regs)
        self.__reg_weights /= sum(self.__reg_weights)
    # Consuming a register does not update the float pick state.
    def pick_float_inputreg(self):
        return random.choices(range(self.num_pickable_floating_regs), self.__reg_weights)[0]
    # Consuming multiple input registers in one go.
    def pick_float_inputregs(self, n: int):
        if DO_ASSERT:
            assert n > 1, "The function pick_float_inputregs should not be used for n < 2. For n = 1, please use pick_float_inputreg."
        return random.choices(range(self.num_pickable_floating_regs), self.__reg_weights, k=n)
    # This updates the floatregstate.
    def pick_float_outputreg(self):
        rd = random.choices(range(self.num_pickable_floating_regs), self.__reg_weights)[0]
        self._update_floatregstate(rd)
        return rd
    # @param outreg the produced register.
    def _update_floatregstate(self, outreg: int):
        if DO_ASSERT:
            assert 0 <= outreg
            assert outreg < self.num_pickable_floating_regs
            assert math.isclose(sum(self.__reg_weights), 1, abs_tol=0.001), f"{sum(self.__reg_weights)} {str(self.__reg_weights)}"
        # The lines here below are a heuristic algorithm to favor more recently produced registers
        if self.num_pickable_floating_regs > 1: # If there is a single one, we do not want to zero its weight
            sum_of_others = np.sum(self.__reg_weights) - self.__reg_weights[outreg]
            for reg_id in range(self.num_pickable_floating_regs):
                # We also do it (for performance) for outreg and we overwrite it later
                self.__reg_weights[reg_id] = self.__reg_weights[reg_id] * (1-REGPICK_PROTUBERANCE_RATIO) / sum_of_others
            self.__reg_weights[outreg] = REGPICK_PROTUBERANCE_RATIO



# for _ in range(100000):
#     tmp = IntRegPickState(32, no_dependency_bias=False)
#     res = tmp.pick_int_outputreg_prime(True)
#     assert res >= 8 and res < 16