# This module picks some random valid CSR operation.

from params.runparams import DO_ASSERT
from rv.csrids import CSR_IDS
from common.TolerateBugs import is_no_interaction_minstret, is_tolerate_boom_minstret
from initialstate.PrivilegeState import PrivilegeStateEnum
from generation.InstructionsCfClass import CSRRegInstruction, CSRImmInstruction, RegImmInstruction
import random

from enum import Enum, auto

class MachineCSROpCandidates64(Enum):
    SCAUSE = auto()
    MCAUSE = auto()
    SSCRATCH = auto()
    MSCRATCH = auto()
    MINSTRET = auto()
    MHPMCOUNTER3 = auto()
    MHPMEVENT31 = auto()

class SupervisorCSROpCandidates(Enum):
    SCAUSE = auto()
    SSCRATCH = auto()

def gen_random_csr_op(fuzzerstate):
    """
    Generate a privileged descent instruction or an mpp/spp write instruction.
    
    Return:
        a list of instructions
    """
    if DO_ASSERT:
        assert fuzzerstate.privilegestate.privstate in (PrivilegeStateEnum.MACHINE, PrivilegeStateEnum.SUPERVISOR)

    if fuzzerstate.privilegestate.privstate == PrivilegeStateEnum.MACHINE:
        target_csr = None
        while target_csr is None or (target_csr == MachineCSROpCandidates64.MINSTRET and is_no_interaction_minstret(fuzzerstate.design_name)):
            target_csr = random.choice(list(MachineCSROpCandidates64))
        if not fuzzerstate.design_has_supervisor_mode:
            while target_csr in (MachineCSROpCandidates64.SCAUSE, MachineCSROpCandidates64.SSCRATCH):
                target_csr = random.choice(list(MachineCSROpCandidates64))

        if target_csr == MachineCSROpCandidates64.SCAUSE:
            # According to the spec, the SCAUSE CSR must be able to hold bits 0 to 4. mret is not required to.
            ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(32), CSR_IDS.SCAUSE)
        elif target_csr == MachineCSROpCandidates64.MCAUSE:
            ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(16), CSR_IDS.MCAUSE)
        elif target_csr == MachineCSROpCandidates64.SSCRATCH:
                ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.SSCRATCH)
        elif target_csr == MachineCSROpCandidates64.MSCRATCH:
                ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MSCRATCH)
        elif target_csr == MachineCSROpCandidates64.MINSTRET:
            if fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak or ("boom" in fuzzerstate.design_name and not is_tolerate_boom_minstret()):
                ret = CSRImmInstruction("csrrwi", 0, random.randrange(16), CSR_IDS.MINSTRET)
            else:

                ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.MINSTRET)
            fuzzerstate.is_minstret_inaccurate_because_ecall_ebreak = False
        elif target_csr == MachineCSROpCandidates64.MHPMCOUNTER3:
            ret = CSRImmInstruction("csrrwi", 0, random.randrange(16), CSR_IDS.MHPMCOUNTER3)
        elif target_csr == MachineCSROpCandidates64.MHPMEVENT31:
            ret = CSRImmInstruction("csrrwi", 0, random.randrange(16), CSR_IDS.MHPMEVENT31)
        else:
            raise Exception("Unexpected target_csr: {}".format(target_csr))
    else:
        target_csr = random.choice(list(SupervisorCSROpCandidates))
        if target_csr == SupervisorCSROpCandidates.SCAUSE:
            ret = CSRImmInstruction("csrrwi", fuzzerstate.intregpickstate.pick_int_outputreg(), random.randrange(32), CSR_IDS.SCAUSE)
        elif target_csr == SupervisorCSROpCandidates.SSCRATCH:
            ret = CSRRegInstruction("csrrw", fuzzerstate.intregpickstate.pick_int_outputreg(), fuzzerstate.intregpickstate.pick_int_inputreg(), CSR_IDS.SSCRATCH)
        else:
            raise Exception("Unexpected target_csr: {}".format(target_csr))
    return ret
