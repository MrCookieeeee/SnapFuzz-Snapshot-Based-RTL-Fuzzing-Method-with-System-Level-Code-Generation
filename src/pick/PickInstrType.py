from generation.InstructionsCfClass import *
from generation.Instructions import INSTRUCTIONS_BY_ISA_CLASS, ISAInstrClass
from common.utils import IntRegIndivState
from collections import defaultdict
import random

# For a given ISAInstrClass, this module helps picking an instruction type.

###
# Helper functions
###

# INSTRTYPE_INITIAL_RELATIVE_WEIGHTS[ISAInstrClass]["add"] = float. Weights will be normalized by instr class.
INSTRTYPE_INITIAL_RELATIVE_WEIGHTS = {
    # For the moment, give all instructions inside the same ISA class the same appearance chance.
    curr_key: dict.fromkeys(curr_instrs, 1) for curr_key, curr_instrs in INSTRUCTIONS_BY_ISA_CLASS.items()
}

def gen_next_instrstr_from_isaclass(isaclass: ISAInstrClass, fuzzerstate) -> str:
    # This global may prevent from copying the dict
    global INSTRTYPE_INITIAL_RELATIVE_WEIGHTS

    keys_and_weights_dict = defaultdict(int, INSTRTYPE_INITIAL_RELATIVE_WEIGHTS[isaclass])

    if isaclass == ISAInstrClass.MEM and not fuzzerstate.intregpickstate.exists_reg_in_state(
            IntRegIndivState.CONSUMED, need_prime=True):
        keys_and_weights_dict["c.lw"] = 0

    if isaclass == ISAInstrClass.SPECIAL:
        fuzzerstate.special_instrs_count += 1

    if DO_ASSERT:
        assert isaclass != ISAInstrClass.REGFSM   , "ISAInstrClass.REGFSM must be treated separately"
        assert isaclass != ISAInstrClass.FPUFSM   , "ISAInstrClass.FPUFSM must be treated separately"
        assert isaclass != ISAInstrClass.EXCEPTION, "ISAInstrClass.EXCEPTION must be treated separately"
        assert isaclass != ISAInstrClass.TVECFSM  , "ISAInstrClass.TVECFSM must be treated separately"
        assert isaclass != ISAInstrClass.PPFSM    , "ISAInstrClass.PPFSM must be treated separately"
        assert isaclass != ISAInstrClass.EPCFSM   , "ISAInstrClass.EPCFSM must be treated separately"

    # ret is the exact instr string, e.g., "add", "c.add"
    ret = None
    while ret is None or keys_and_weights_dict[ret] == 0:
        ret = random.choices(list(keys_and_weights_dict.keys()), weights=keys_and_weights_dict.values())[0]
    return ret
