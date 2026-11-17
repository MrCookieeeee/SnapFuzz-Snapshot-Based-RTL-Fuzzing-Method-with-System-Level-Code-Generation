# This module is responsible for choosing the memory operation addresses and address registers.
from typing import TYPE_CHECKING
from params.runparams import DO_ASSERT
import random

from params.fuzzparams import MemaddrPickPolicy, MEMADDR_PICK_POLICY_WEIGTHS

if TYPE_CHECKING:
    from src.initialstate.FuzzerState import FuzzerState

def is_instrstr_load(instr_str: str):
    """
    Helper function for the basic blocks
    """
    return instr_str in ("lb", "lh", "lhu", "lw", "lwu", "flw", "ld", "fld",  \
                         "c.lw")   # rv32c
    # Note: AMO/LR/SC are NOT loads — they all need store locations since they write to memory

def get_alignment_bits(instr_str: str):
    """
    Helper function for the basic blocks
    """
    if instr_str in ("sb", "lb", "lbu"):
        return 0
    elif instr_str in ("sh", "lh", "lhu"):
        return 1
    elif instr_str in ("sw", "lw", "lwu", "flw", "fsw", "c.lw",
                       "lr.w", "sc.w",
                       "amoswap.w", "amoadd.w", "amoxor.w", "amoand.w", "amoor.w",
                       "amomin.w", "amomax.w", "amominu.w", "amomaxu.w"):
        return 2
    elif instr_str in ("sd", "ld", "fld", "fsd",
                       "lr.d", "sc.d",
                       "amoswap.d", "amoadd.d", "amoxor.d", "amoand.d", "amoor.d",
                       "amomin.d", "amomax.d", "amominu.d", "amomaxu.d"):
        return 3
    else:
        raise ValueError(f"Unexpected memory instruction string: `{instr_str}`")

def pick_memop_addr(fuzzerstate: 'FuzzerState', is_curr_load: bool, alignment_bits: int):
    """
    Does not update the memview of the fuzzerstate.

    Args:
        is_curr_load: True if load, False if store
        alignment_bits: 0, 1, 2 or 3
    
    Return:
        the address
    """
    if DO_ASSERT:
        assert 0 <= alignment_bits <= 3,f"Invalid alignment_bits: {alignment_bits}" 

    # Ensure we don't make a wrong choice
    curr_pick_type = None
    while curr_pick_type is None or MEMADDR_PICK_POLICY_WEIGTHS[is_curr_load][curr_pick_type] == 0:
        curr_pick_type = random.choices(list(MEMADDR_PICK_POLICY_WEIGTHS[is_curr_load].keys()), weights=MEMADDR_PICK_POLICY_WEIGTHS[is_curr_load].values())[0]

    if curr_pick_type == MemaddrPickPolicy.MEM_ANY_STORELOC:
        # Pick a store location
        ret_addr = fuzzerstate.memstorestate.pick_store_location(alignment_bits)
        if not is_curr_load:
            fuzzerstate.memstorestate.last_store_addr = ret_addr
        return ret_addr
    
    elif curr_pick_type == MemaddrPickPolicy.MEM_ANY:
        if DO_ASSERT:
            assert is_curr_load
        if fuzzerstate.design_name == "rocket":
            # Exercise data reads sharing the final instruction cache line.
            width = 1 << alignment_bits
            final_end = fuzzerstate.final_bb_base_addr + 4 * len(fuzzerstate.final_bb)
            line_end = ((final_end - 1) // 64 + 1) * 64
            candidates = [addr for addr in range((final_end + width - 1) // width * width,
                                                 line_end - width + 1, width)
                          if addr + width < fuzzerstate.memsize
                          and fuzzerstate.memview_blacklist.is_mem_range_free(addr, addr + width)]
            if candidates and random.random() < 0.125:
                return random.choice(candidates)
        # Pick any location
        ret_addr = fuzzerstate.memview_blacklist.gen_random_free_addr(alignment_bits, 1 << alignment_bits, 0, fuzzerstate.memview_blacklist.memsize)
        if DO_ASSERT:
            assert ret_addr >= 0
            assert ret_addr + (1 << alignment_bits) < fuzzerstate.memsize
        return ret_addr
    else:
        raise NotImplementedError(f"Unimplemented MemaddrPickPolicy: `{curr_pick_type}`.")
