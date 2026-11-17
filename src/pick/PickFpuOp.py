import random
from typing import TYPE_CHECKING

from params.runparams import DO_ASSERT
from params.fuzzparams import FPU_ENDIS_REGISTER_ID

from initialstate.PrivilegeState import PrivilegeStateEnum
from generation.InstructionsCfClass import CSRRegInstruction, RegImmInstruction
from rv.csrids import CSR_IDS

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState

ROUNDING_MODES = [0, 1, 2, 3, 4] # The non-reserved ones

def __pick_rounding_mode():
    import random
    return random.sample(ROUNDING_MODES, 1)[0]

def create_rmswitch_instrobjs(fuzzerstate):
    # Check that the FPU exists and is activated
    if DO_ASSERT:
        assert fuzzerstate.design_has_fpu
        assert fuzzerstate.is_fpu_activated
    # Put a random (valid) value to rm
    new_rm = __pick_rounding_mode()
    rinterm = fuzzerstate.intregpickstate.pick_int_inputreg_nonzero()
    # rd = fuzzerstate.intregpickstate.pick_int_outputreg() # Can be equal to rinterm
    rd = 0 # FUTURE WARL
    # Either through the frm CSR, or through the fcsr register
    use_frm_csr = random.randint(0, 1)
    if use_frm_csr:
        return [
            # Put the rounding mode to rinterm, and unset the flag bits
            RegImmInstruction("addi", rinterm, 0, new_rm, fuzzerstate.is_design_64bit),
            CSRRegInstruction("csrrw", rd, rinterm, CSR_IDS.FRM)
        ]
    else:
        return [
            # Put the rounding mode to rinterm, and unset the flag bits
            RegImmInstruction("addi", rinterm, 0, new_rm << 5, fuzzerstate.is_design_64bit),
            CSRRegInstruction("csrrw", rd, rinterm, CSR_IDS.FCSR)
        ]


def gen_fpufsm_instrs(fuzzerstate: 'FuzzerState'):
    """ 
        1. Enable/disable FPU  
        2. Change rounding mode ?
    """

    if DO_ASSERT:
        assert fuzzerstate.design_has_fpu
        assert fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE

    if random.random() < fuzzerstate.proba_turn_on_off_fpu_again:
        rd = 0 # FUTURE WARL
        if fuzzerstate.is_fpu_activated:
            return [CSRRegInstruction("csrrs", rd, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
        else:
            return [CSRRegInstruction("csrrc", rd, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]

    # If the FPU is off, then we turn the FPU on.
    if fuzzerstate.is_fpu_activated:
        # Else, we arbitrate randomly between changing the rounding mode and turning off the FPU
        do_change_rounding_mode = random.random() < fuzzerstate.proba_change_rm
        if do_change_rounding_mode:
            return create_rmswitch_instrobjs(fuzzerstate)
        else:
            fuzzerstate.is_fpu_activated = False
            rd = 0 # Do not read the value because for triaging we want to be ablw to remove these instructions
            return [CSRRegInstruction("csrrc", rd, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
    else:
        rd = 0 # WARL
        fuzzerstate.is_fpu_activated = True
        return [CSRRegInstruction("csrrs", rd, FPU_ENDIS_REGISTER_ID, CSR_IDS.MSTATUS)]
