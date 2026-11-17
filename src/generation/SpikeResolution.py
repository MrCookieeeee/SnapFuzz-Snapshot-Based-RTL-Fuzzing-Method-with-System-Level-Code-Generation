import os
import random
import itertools
from typing import TYPE_CHECKING
from params.runparams import DO_ASSERT, NO_REMOVE_TMPFILES
from common.Spike import SPIKE_STARTADDR

from generation.InstructionsCfClass import PlaceholderProducerInstr0, PlaceholderProducerInstr1, BranchInstruction, PlaceholderConsumerInstr
from initialstate.FuzzerState import FuzzerState

from generation.GenElf import gen_elf_from_bbs
from common.GetCfgs import get_design_march_flags_nocompressed
from common.Spike import run_trace_regs_at_pc_locs

if TYPE_CHECKING:
    from initialstate.FuzzerState import FuzzerState

def _transmit_addrs_to_producers_for_spike_resolution(fuzzerstate: 'FuzzerState'):
    """
    遍历 fuzzing 生成的所有基本块, 为每个带有producer_id的占位指令分配一个确定的跳转目标地址, 并把这个目标地址传递给 spike_resolution_offset
    """
    for bb_instrlist in fuzzerstate.instr_objs_seq:
        for bb_instr in bb_instrlist:
            if isinstance(bb_instr, PlaceholderProducerInstr0):
                if bb_instr.producer_id not in fuzzerstate.producer_id_to_tgtaddr:
                    fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id] = random.randrange(1 << 30) << 2

                bb_instr.spike_resolution_offset = fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id]
            elif isinstance(bb_instr, PlaceholderProducerInstr1):
                bb_instr.spike_resolution_offset = fuzzerstate.producer_id_to_tgtaddr[bb_instr.producer_id]

def gen_regdump_reqs(fuzzerstate: 'FuzzerState'):
    """
    Generates the register dump requests made to spike
    
    Returns:
        register dump requests: an iterable of pairs (pc, reg to dump) in program order
    """
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    ret = []
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        curr_addr = bb_start_addr
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            # All we need is the value of the dependent register at consumption time.
            if isinstance(bb_instr, PlaceholderConsumerInstr):
                ret.append((curr_addr, False, bb_instr.rdep))
            # For branches, we need to know the val of both operands to generate a suitable opcode later.
            if isinstance(bb_instr, BranchInstruction):
                # if not bb_instr.plan_taken:
                ret.append((curr_addr, False, bb_instr.rs1)) # rs1 is the first  dependent register.
                ret.append((curr_addr, False, bb_instr.rs2)) # rs2 is the second dependent register.
            
            # compressed and non-compressed instrs
            if bb_instr.iscompressed:    
                curr_addr += 2 
            else:
                curr_addr += 4

    return ret

def _feed_regdump_to_instrs(fuzzerstate: 'FuzzerState', regdumps: list):
    """
    From the output of the regdump, distributes the values to the instructions
    
    Returns:
        nothing
    """
    if DO_ASSERT:
        assert len(fuzzerstate.instr_objs_seq) == len(fuzzerstate.bb_start_addr_seq)

    producer_id_to_rdepval = dict() # producer_id_to_rdepval[producer_id] = tgt_addr

    index_in_regdump = 0
    for bb_start_addr, bb_instrs in zip(fuzzerstate.bb_start_addr_seq, fuzzerstate.instr_objs_seq):
        for bb_instr_id, bb_instr in enumerate(bb_instrs):
            # For consumers, we just place the register value for the producers
            if isinstance(bb_instr, PlaceholderConsumerInstr):
                # if DO_ASSERT:
                #     if fuzzerstate.is_design_64bit:
                #         assert regdumps[index_in_regdump] < 1 << 30, f"For more efficient offset generation, we ask the dependent register to be strictly less than 1 << 30. This is typically ensured by the pre-consumer. Producer id: {bb_instr.producer_id}"

                producer_id_to_rdepval[bb_instr.producer_id] = regdumps[index_in_regdump]
                index_in_regdump += 1

            if isinstance(bb_instr, BranchInstruction):
                # First, we get rs1.
                branch_rs1_content = regdumps[index_in_regdump]
                index_in_regdump += 1
                # Second, we get rs2.
                branch_rs2_content = regdumps[index_in_regdump]
                index_in_regdump += 1
                # Now, we can redetermine the branch opcode depending on the register values
                bb_instr.select_suitable_opcode(branch_rs1_content, branch_rs2_content)

    # Feed the consumer-level information into the producers
    for bb_instrlist in fuzzerstate.instr_objs_seq:
        for bb_instr in bb_instrlist:
            if isinstance(bb_instr, PlaceholderProducerInstr0) or isinstance(bb_instr, PlaceholderProducerInstr1):
                if bb_instr.producer_id in producer_id_to_rdepval:
                    # Rationale: target_addr = rdep ^ rprod, where target_addr is spike_resolution_offset
                    bb_instr.rtl_offset = producer_id_to_rdepval[bb_instr.producer_id] ^ bb_instr.spike_resolution_offset ^ SPIKE_STARTADDR
                else:
                    # If this producer is never used, then we need to ensure that it remains the same as in the Spike resolution
                    bb_instr.rtl_offset = bb_instr.spike_resolution_offset

# ============================================================================
# ISA SIM
#     80008814:	00023137          	lui	sp,0x23                   FREE -> PRODUCED0
#     8000881c:	e0010113          	add	sp,sp,-512 # 0x22e00      PRODUCED0 -> PRODUCED1
# 
#     8000888c:	01e17133          	and	t1,t1,t5
#     80008890:	01e4f4b3          	and	s1,s1,t5
#     80008894:	01f14133          	xor	sp,sp,t6                  PRODUCED1 -> CONSUMED
#     80008898:	000102e7          	jalr	t0,sp                 CONSUMED -> FREE
#     sp = 80022e00
#
# When doing spike, there is no dependent reg (e.g., t1), so xor with t6(fixed val 0x80000000) to get a legal addr
# When doing RTL, however, we now know the dependent reg (t1) after spike resolution, so the lui/addi imm are different from ISA  
# The rtl offest can only be calculated after spike resolution is done
# For how to cal rtl offset, see this line: bb_instr.rtl_offset = producer_id_to_rdepval[bb_instr.producer_id] ^ bb_instr.spike_resolution_offset ^ SPIKE_STARTADDR (only a few line above)
#
# RTL SIM
#     80008814:	7ffdd137          	lui	sp,0x7ffdd
#     8000881c:	38510113          	add	sp,sp,901 # 0x7ffdd385
                    
#     8000888c:	01e17133          	and	t1,t1,t5
#     80008890:	01e4f4b3          	and	s1,s1,t5
#     80008894:	0024c133          	xor	sp,s1,t1
#     80008898:	000102e7          	jalr	t0,sp
#     sp = 80022e00
# ============================================================================
def spike_resolution(fuzzerstate: 'FuzzerState', check_pc_spike_again: bool = False):
    """
    Takes a fuzzerstate after its basic blocks were generated.
    Does the address resolution in place in the fuzzerstate
    
    Returns: 
        the list of expected register values.
    """
    design_name = fuzzerstate.design_name
    _transmit_addrs_to_producers_for_spike_resolution(fuzzerstate)

    spike_resolution_elfpath = gen_elf_from_bbs(fuzzerstate, True, 'spikeresol', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)

    # request to dump reg in intermidiate program
    regdump_reqs = gen_regdump_reqs(fuzzerstate)
    flat_instr_objs = list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq))
    # len(flat_instr_objs)+1: the +1 is to reach the final basic block and thereby overwrite the potential destination register of a jal/jalr

    """ Spike 执行的结果 """
    regvals, (finalintregvals_spikeresol, finalfpuregvals_spikeresol, finalcsrvals_spikeresol) = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str(),
                                                                                                  spike_resolution_elfpath, 
                                                                                                  get_design_march_flags_nocompressed(design_name), 
                                                                                                  SPIKE_STARTADDR, 
                                                                                                  regdump_reqs, True, 
                                                                                                  fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR, 
                                                                                                  fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, 
                                                                                                  fuzzerstate.design_has_fpud,
                                                                                                  final_csr_ids=fuzzerstate.final_csr_ids)
    if not NO_REMOVE_TMPFILES:
        os.remove(spike_resolution_elfpath)
        del spike_resolution_elfpath

    # --------------------------------------------------------------------------------------------------------------------------------------------------
    # IMPORTANT: We reset the randomness here to have deterministic branch instructions.
    # (Rare) example where it matters: assume we need to pop the last bb, say with id 20. Then we could have a bug with request size 19 but not with request size 20, or vice versa.
    # 在这里只是设定好种子，后续调用random的时候才会产生真正的随机数
    # 注意，对于相同的种子，产生的随机数也是一样的，这保证了结果的可复现
    # --------------------------------------------------------------------------------------------------------------------------------------------------
    random.seed(fuzzerstate.randseed) # We could as well seed with zero here.

    # 把PlaceHolder补上Spike解出的地址 
    _feed_regdump_to_instrs(fuzzerstate, regvals)

    return finalintregvals_spikeresol[1:], finalfpuregvals_spikeresol, finalcsrvals_spikeresol



def spike_resolution_for_reduction(fuzzerstate: 'FuzzerState', check_pc_spike_again: bool = False):
    """
    For Reduction
    """
    design_name = fuzzerstate.design_name
    _transmit_addrs_to_producers_for_spike_resolution(fuzzerstate)

    spike_resolution_elfpath = gen_elf_from_bbs(fuzzerstate, True, 'spikeresol', fuzzerstate.instance_to_str_for_deduction(), SPIKE_STARTADDR)
    print(f"success generate spike file:   {spike_resolution_elfpath}")

    # request to dump reg in intermidiate program
    regdump_reqs = gen_regdump_reqs(fuzzerstate)
    flat_instr_objs = list(itertools.chain.from_iterable(fuzzerstate.instr_objs_seq))
    # len(flat_instr_objs)+1: the +1 is to reach the final basic block and thereby overwrite the potential destination register of a jal/jalr

    regvals, (finalintregvals_spikeresol, finalfpuregvals_spikeresol, finalcsrvals_spikeresol) = run_trace_regs_at_pc_locs(fuzzerstate.instance_to_str_for_deduction(),
                                                                                                  spike_resolution_elfpath, 
                                                                                                  get_design_march_flags_nocompressed(design_name), 
                                                                                                  SPIKE_STARTADDR, 
                                                                                                  regdump_reqs, True, 
                                                                                                  fuzzerstate.final_bb_base_addr+SPIKE_STARTADDR, 
                                                                                                  fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, 
                                                                                                  fuzzerstate.design_has_fpud,
                                                                                                  final_csr_ids=fuzzerstate.final_csr_ids)
    if not NO_REMOVE_TMPFILES:
        os.remove(spike_resolution_elfpath)
        del spike_resolution_elfpath
    
    random.seed(fuzzerstate.randseed) # We could as well seed with zero here.

    _feed_regdump_to_instrs(fuzzerstate, regvals)

    return finalintregvals_spikeresol[1:], finalfpuregvals_spikeresol, finalcsrvals_spikeresol




    # Use spike to check the rtl elf if requested
    if check_pc_spike_again:
        # Generate the RTL ELF, but located for spike at SPIKE_STARTADDR
        rtl_spike_elfpath = gen_elf_from_bbs(fuzzerstate, False, 'spikedoublecheck', fuzzerstate.instance_to_str(), SPIKE_STARTADDR)
        if NO_REMOVE_TMPFILES:
            print('rtl_spike_elfpath:', rtl_spike_elfpath)
        rtl_spike_pc_seq, (finalintregvals_spikecheck, finalfpuregvals_spikecheck) = run_trace_all_pcs(fuzzerstate.instance_to_str(), rtl_spike_elfpath, get_design_march_flags_nocompressed(design_name), len(flat_instr_objs)+1, SPIKE_STARTADDR, True,  fuzzerstate.num_pickable_floating_regs if fuzzerstate.design_has_fpu else 0, fuzzerstate.design_has_fpud, fuzzerstate)
        if not NO_REMOVE_TMPFILES:
            os.remove(rtl_spike_elfpath)
            del rtl_spike_elfpath

        # Check PC sequence
        _check_pc_trace_from_spike(fuzzerstate, rtl_spike_pc_seq)
        # Check register matching
        for reg_id in range(1, fuzzerstate.num_pickable_regs):
            # The transient registers are not expected to match.
            if fuzzerstate.intregpickstate.get_regstate(reg_id) in (IntRegIndivState.FREE, IntRegIndivState.CONSUMED):
                assert finalintregvals_spikeresol[reg_id] == finalintregvals_spikecheck[reg_id], f"Mismatch in x{reg_id} value. Resolution: `{hex(finalintregvals_spikeresol[reg_id])}`, check: `{hex(finalintregvals_spikecheck[reg_id])}`. Reg state: `{fuzzerstate.intregpickstate.get_regstate(reg_id)}`."
        if fuzzerstate.design_has_fpu:
            for reg_id in range(fuzzerstate.num_pickable_floating_regs):
                assert finalfpuregvals_spikeresol[reg_id] == finalfpuregvals_spikecheck[reg_id], f"Mismatch in f{reg_id} value. Resolution: `{hex(finalfpuregvals_spikeresol[reg_id])}`, check: `{hex(finalintregvals_spikecheck[reg_id])}`."
